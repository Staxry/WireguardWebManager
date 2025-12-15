#!/usr/bin/env python3
"""
Rate Limiting система для WireGuard Web Management Interface
Защита от брутфорс атак и злоупотреблений
"""

import time
import json
import os
from collections import defaultdict, deque
from functools import wraps
from flask import request, jsonify, session
from datetime import datetime, timedelta

# Конфигурация rate limiting (смягченные лимиты)
RATE_LIMITS = {
    'login': {'requests': 10, 'window': 300},      # 10 попыток за 5 минут
    'api_general': {'requests': 1000, 'window': 60},  # 1000 запросов в минуту
    'api_write': {'requests': 200, 'window': 60},     # 200 операций записи в минуту
    'web_general': {'requests': 2000, 'window': 60},  # 2000 веб-запросов в минуту
    'password_change': {'requests': 50, 'window': 3600},  # 50 смен пароля в час
    'username_change': {'requests': 50, 'window': 3600},  # 50 смен имени в час
}

# Хранилище для счетчиков (в продакшене лучше использовать Redis)
request_counts = defaultdict(lambda: defaultdict(deque))
blocked_ips = {}

# Путь к файлу с заблокированными IP
# Путь к корню проекта (на уровень выше пакета wg_web)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(PROJECT_ROOT, 'logs')
BLOCKED_IPS_FILE = os.path.join(LOG_DIR, 'blocked_ips.json')

def ensure_log_directory():
    """Создание директории для логов"""
    log_dir = os.path.dirname(BLOCKED_IPS_FILE)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, mode=0o750)

def load_blocked_ips():
    """Загрузка заблокированных IP из файла"""
    global blocked_ips
    ensure_log_directory()
    
    try:
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, 'r') as f:
                data = json.load(f)
                # Фильтруем истекшие блокировки
                current_time = time.time()
                blocked_ips = {
                    ip: info for ip, info in data.items()
                    if info.get('expires_at', 0) > current_time
                }
                save_blocked_ips()  # Сохраняем очищенный список
    except Exception as e:
        print(f"Ошибка загрузки заблокированных IP: {e}")
        blocked_ips = {}

def save_blocked_ips():
    """Сохранение заблокированных IP в файл"""
    ensure_log_directory()
    
    try:
        with open(BLOCKED_IPS_FILE, 'w') as f:
            json.dump(blocked_ips, f, indent=2)
    except Exception as e:
        print(f"Ошибка сохранения заблокированных IP: {e}")

def get_client_ip():
    """Получение IP адреса клиента"""
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        return request.environ['REMOTE_ADDR']
    else:
        # Берем первый IP из списка (реальный клиент)
        return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()

def is_ip_blocked(ip_address):
    """Проверка, заблокирован ли IP адрес"""
    if ip_address in blocked_ips:
        block_info = blocked_ips[ip_address]
        if block_info.get('expires_at', 0) > time.time():
            return True, block_info
        else:
            # Блокировка истекла, удаляем
            del blocked_ips[ip_address]
            save_blocked_ips()
    
    return False, None

def block_ip(ip_address, duration=3600, reason="Rate limit exceeded"):
    """Блокировка IP адреса"""
    expires_at = time.time() + duration
    blocked_ips[ip_address] = {
        'blocked_at': time.time(),
        'expires_at': expires_at,
        'reason': reason,
        'attempts': blocked_ips.get(ip_address, {}).get('attempts', 0) + 1
    }
    save_blocked_ips()
    
    # Логируем блокировку
    from .audit_log import log_action
    log_action('ip_blocked', 
              details={
                  'ip_address': ip_address,
                  'reason': reason,
                  'duration': duration,
                  'expires_at': datetime.fromtimestamp(expires_at).isoformat()
              })

def check_rate_limit(limit_type, identifier=None):
    """
    Проверка rate limit для определенного типа запроса
    
    Args:
        limit_type (str): Тип лимита из RATE_LIMITS
        identifier (str): Дополнительный идентификатор (по умолчанию IP)
    
    Returns:
        tuple: (allowed, remaining_requests, reset_time)
    """
    if limit_type not in RATE_LIMITS:
        return True, float('inf'), 0
    
    config = RATE_LIMITS[limit_type]
    max_requests = config['requests']
    window = config['window']
    
    # Используем IP как идентификатор по умолчанию
    if identifier is None:
        identifier = get_client_ip()
    
    current_time = time.time()
    window_start = current_time - window
    
    # Очищаем старые записи
    requests_deque = request_counts[limit_type][identifier]
    while requests_deque and requests_deque[0] < window_start:
        requests_deque.popleft()
    
    # Проверяем лимит
    if len(requests_deque) >= max_requests:
        reset_time = requests_deque[0] + window
        return False, 0, reset_time
    
    # Добавляем текущий запрос
    requests_deque.append(current_time)
    
    remaining = max_requests - len(requests_deque)
    reset_time = current_time + window
    
    return True, remaining, reset_time

def rate_limit(limit_type, block_on_exceed=False, block_duration=3600):
    """
    Декоратор для применения rate limiting
    
    Args:
        limit_type (str): Тип лимита из RATE_LIMITS
        block_on_exceed (bool): Блокировать IP при превышении лимита
        block_duration (int): Длительность блокировки в секундах
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = get_client_ip()
            
            # Проверяем, не заблокирован ли IP
            is_blocked, block_info = is_ip_blocked(client_ip)
            if is_blocked:
                expires_at = datetime.fromtimestamp(block_info['expires_at'])
                
                if request.path.startswith('/api/'):
                    return jsonify({
                        'error': 'IP address blocked',
                        'reason': block_info.get('reason', 'Rate limit exceeded'),
                        'expires_at': expires_at.isoformat(),
                        'attempts': block_info.get('attempts', 1)
                    }), 429
                else:
                    from flask import render_template
                    return render_template('blocked.html', 
                                         block_info=block_info,
                                         expires_at=expires_at), 429
            
            # Проверяем rate limit
            allowed, remaining, reset_time = check_rate_limit(limit_type, client_ip)
            
            if not allowed:
                # Превышен лимит
                if block_on_exceed:
                    reason = f"Rate limit exceeded for {limit_type}"
                    block_ip(client_ip, block_duration, reason)
                
                reset_datetime = datetime.fromtimestamp(reset_time)
                
                if request.path.startswith('/api/'):
                    return jsonify({
                        'error': 'Rate limit exceeded',
                        'limit_type': limit_type,
                        'reset_at': reset_datetime.isoformat(),
                        'blocked': block_on_exceed
                    }), 429
                else:
                    from flask import render_template
                    return render_template('rate_limited.html',
                                         limit_type=limit_type,
                                         reset_at=reset_datetime,
                                         blocked=block_on_exceed), 429
            
            # Добавляем заголовки с информацией о лимитах
            response = f(*args, **kwargs)
            
            if hasattr(response, 'headers'):
                response.headers['X-RateLimit-Limit'] = str(RATE_LIMITS[limit_type]['requests'])
                response.headers['X-RateLimit-Remaining'] = str(remaining)
                response.headers['X-RateLimit-Reset'] = str(int(reset_time))
            
            return response
        
        return decorated_function
    return decorator

def get_rate_limit_status(limit_type, identifier=None):
    """Получение текущего статуса rate limit"""
    allowed, remaining, reset_time = check_rate_limit(limit_type, identifier)
    
    return {
        'limit_type': limit_type,
        'allowed': allowed,
        'remaining': remaining,
        'reset_at': datetime.fromtimestamp(reset_time).isoformat(),
        'window': RATE_LIMITS.get(limit_type, {}).get('window', 0),
        'max_requests': RATE_LIMITS.get(limit_type, {}).get('requests', 0)
    }

def get_blocked_ips_info():
    """Получение информации о заблокированных IP"""
    current_time = time.time()
    active_blocks = []
    
    for ip, info in blocked_ips.items():
        if info.get('expires_at', 0) > current_time:
            active_blocks.append({
                'ip_address': ip,
                'blocked_at': datetime.fromtimestamp(info['blocked_at']).isoformat(),
                'expires_at': datetime.fromtimestamp(info['expires_at']).isoformat(),
                'reason': info.get('reason', 'Unknown'),
                'attempts': info.get('attempts', 1),
                'remaining_time': int(info['expires_at'] - current_time)
            })
    
    return sorted(active_blocks, key=lambda x: x['expires_at'], reverse=True)

def unblock_ip(ip_address):
    """Разблокировка IP адреса"""
    if ip_address in blocked_ips:
        del blocked_ips[ip_address]
        save_blocked_ips()
        
        # Логируем разблокировку
        from .audit_log import log_action
        log_action('ip_unblocked', 
                  details={'ip_address': ip_address})
        return True
    
    return False

def cleanup_old_requests():
    """Очистка старых записей запросов"""
    current_time = time.time()
    
    for limit_type in request_counts:
        max_window = RATE_LIMITS.get(limit_type, {}).get('window', 3600)
        cutoff_time = current_time - max_window * 2  # Удаляем записи старше двойного окна
        
        for identifier in list(request_counts[limit_type].keys()):
            requests_deque = request_counts[limit_type][identifier]
            
            # Удаляем старые записи
            while requests_deque and requests_deque[0] < cutoff_time:
                requests_deque.popleft()
            
            # Удаляем пустые деки
            if not requests_deque:
                del request_counts[limit_type][identifier]

def get_rate_limit_stats():
    """Получение статистики rate limiting"""
    stats = {
        'total_blocked_ips': len(blocked_ips),
        'active_blocks': len([ip for ip, info in blocked_ips.items() 
                             if info.get('expires_at', 0) > time.time()]),
        'limit_types': {},
        'top_ips': {}
    }
    
    # Статистика по типам лимитов
    for limit_type in RATE_LIMITS:
        if limit_type in request_counts:
            active_identifiers = len(request_counts[limit_type])
            total_requests = sum(len(deque_obj) for deque_obj in request_counts[limit_type].values())
            
            stats['limit_types'][limit_type] = {
                'active_identifiers': active_identifiers,
                'total_requests': total_requests,
                'config': RATE_LIMITS[limit_type]
            }
    
    # Топ IP по количеству запросов
    ip_requests = defaultdict(int)
    for limit_type in request_counts:
        for identifier, requests_deque in request_counts[limit_type].items():
            if '.' in identifier or ':' in identifier:  # Проверяем что это IP
                ip_requests[identifier] += len(requests_deque)
    
    stats['top_ips'] = dict(sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)[:10])
    
    return stats

# Инициализация при импорте модуля
load_blocked_ips()

if __name__ == '__main__':
    # Тестирование rate limiter
    print("Тестирование Rate Limiter...")
    
    # Тест проверки лимита
    for i in range(7):
        allowed, remaining, reset_time = check_rate_limit('login', '192.168.1.100')
        print(f"Попытка {i+1}: allowed={allowed}, remaining={remaining}")
        
        if not allowed:
            print("Лимит превышен!")
            break
    
    # Тест блокировки IP
    block_ip('192.168.1.200', 300, "Test block")
    is_blocked, block_info = is_ip_blocked('192.168.1.200')
    print(f"IP заблокирован: {is_blocked}, info: {block_info}")
    
    # Статистика
    stats = get_rate_limit_stats()
    print(f"Статистика: {stats}")
    
    print("Тестирование завершено!")

