#!/usr/bin/env python3
"""
Система аудита и логирования действий администратора
"""

import json
import os
from datetime import datetime
from functools import wraps
from flask import request, session

# Путь к файлу логов
# Путь к корню проекта (на уровень выше пакета wg_web)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(PROJECT_ROOT, 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'audit.log')

def ensure_log_directory():
    """Создание директории для логов если она не существует"""
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR, mode=0o750)

def get_client_ip():
    """Получение IP адреса клиента (безопасно, с фоллбеком)"""
    try:
        # Берем первый IP из X-Forwarded-For если есть
        xff = request.headers.get('X-Forwarded-For') or request.environ.get('HTTP_X_FORWARDED_FOR')
        if xff:
            return xff.split(',')[0].strip()
        # Иначе стандартный адрес
        return (getattr(request, 'remote_addr', None)
                or request.environ.get('REMOTE_ADDR')
                or 'unknown')
    except Exception:
        return 'unknown'

def log_action(action, details=None, status='success', error_message=None):
    """
    Логирование действия администратора
    
    Args:
        action (str): Тип действия (login, logout, create_client, delete_client, etc.)
        details (dict): Дополнительные детали действия
        status (str): Статус действия (success, error, warning)
        error_message (str): Сообщение об ошибке если есть
    """
    ensure_log_directory()
    
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'username': session.get('username', 'unknown'),
        'action': action,
        'status': status,
        'ip_address': get_client_ip(),
        'user_agent': request.headers.get('User-Agent', 'unknown'),
        'session_id': session.get('session_id', 'unknown')
    }
    
    if details:
        log_entry['details'] = details
    
    if error_message:
        log_entry['error_message'] = error_message
    
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
    except Exception as e:
        print(f"Ошибка записи в лог: {e}")

def log_decorator(action_name):
    """
    Декоратор для автоматического логирования действий
    
    Usage:
        @log_decorator('create_client')
        def create_client():
            # код функции
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs)
                log_action(action_name, details={'function': func.__name__})
                return result
            except Exception as e:
                log_action(action_name, status='error', error_message=str(e))
                raise
        return wrapper
    return decorator

def get_audit_logs(limit=100, filter_action=None, filter_username=None, start_date=None, end_date=None):
    """
    Получение логов аудита с фильтрацией
    
    Args:
        limit (int): Максимальное количество записей
        filter_action (str): Фильтр по типу действия
        filter_username (str): Фильтр по имени пользователя
        start_date (datetime): Начальная дата
        end_date (datetime): Конечная дата
    
    Returns:
        list: Список записей логов
    """
    if not os.path.exists(LOG_FILE):
        return []
    
    logs = []
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    try:
                        log_entry = json.loads(line.strip())
                        
                        # Применяем фильтры
                        if filter_action and log_entry.get('action') != filter_action:
                            continue
                        
                        if filter_username and log_entry.get('username') != filter_username:
                            continue
                        
                        if start_date:
                            log_time = datetime.fromisoformat(log_entry['timestamp'])
                            if log_time < start_date:
                                continue
                        
                        if end_date:
                            log_time = datetime.fromisoformat(log_entry['timestamp'])
                            if log_time > end_date:
                                continue
                        
                        logs.append(log_entry)
                        
                        if len(logs) >= limit:
                            break
                            
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        print(f"Ошибка чтения логов: {e}")
    
    # Возвращаем в обратном порядке (новые сначала)
    return list(reversed(logs))

def get_audit_stats():
    """
    Получение статистики по логам аудита
    
    Returns:
        dict: Статистика действий
    """
    logs = get_audit_logs(limit=1000)
    
    stats = {
        'total_actions': len(logs),
        'actions_by_type': {},
        'actions_by_user': {},
        'actions_by_status': {},
        'recent_errors': [],
        'top_ips': {}
    }
    
    for log in logs:
        # Статистика по типам действий
        action = log.get('action', 'unknown')
        stats['actions_by_type'][action] = stats['actions_by_type'].get(action, 0) + 1
        
        # Статистика по пользователям
        username = log.get('username', 'unknown')
        stats['actions_by_user'][username] = stats['actions_by_user'].get(username, 0) + 1
        
        # Статистика по статусам
        status = log.get('status', 'unknown')
        stats['actions_by_status'][status] = stats['actions_by_status'].get(status, 0) + 1
        
        # Последние ошибки
        if status == 'error' and len(stats['recent_errors']) < 10:
            stats['recent_errors'].append({
                'timestamp': log['timestamp'],
                'action': action,
                'error': log.get('error_message', 'Unknown error')
            })
        
        # Топ IP адресов
        ip = log.get('ip_address', 'unknown')
        stats['top_ips'][ip] = stats['top_ips'].get(ip, 0) + 1
    
    # Сортируем топ IP
    stats['top_ips'] = dict(sorted(stats['top_ips'].items(), key=lambda x: x[1], reverse=True)[:10])
    
    return stats

def cleanup_old_logs(days_to_keep=30):
    """
    Очистка старых логов
    
    Args:
        days_to_keep (int): Количество дней для хранения логов
    """
    if not os.path.exists(LOG_FILE):
        return
    
    cutoff_date = datetime.now().timestamp() - (days_to_keep * 24 * 60 * 60)
    temp_file = LOG_FILE + '.tmp'
    
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as infile, \
             open(temp_file, 'w', encoding='utf-8') as outfile:
            
            for line in infile:
                if line.strip():
                    try:
                        log_entry = json.loads(line.strip())
                        log_time = datetime.fromisoformat(log_entry['timestamp']).timestamp()
                        
                        if log_time >= cutoff_date:
                            outfile.write(line)
                    except (json.JSONDecodeError, ValueError):
                        # Пропускаем поврежденные записи
                        continue
        
        # Заменяем оригинальный файл
        os.replace(temp_file, LOG_FILE)
        log_action('cleanup_logs', details={'days_kept': days_to_keep})
        
    except Exception as e:
        if os.path.exists(temp_file):
            os.remove(temp_file)
        print(f"Ошибка очистки логов: {e}")

# Предопределенные типы действий для удобства
class AuditActions:
    LOGIN = 'login'
    LOGOUT = 'logout'
    LOGIN_FAILED = 'login_failed'
    CREATE_CLIENT = 'create_client'
    DELETE_CLIENT = 'delete_client'
    DOWNLOAD_CONFIG = 'download_config'
    VIEW_QR = 'view_qr'
    CHANGE_PASSWORD = 'change_password'
    PASSWORD_CHANGED = 'password_changed'
    VIEW_CLIENTS = 'view_clients'
    SYSTEM_DIAGNOSTIC = 'system_diagnostic'
    FIX_INTERNET = 'fix_internet'
    SESSION_TIMEOUT = 'session_timeout'
    IP_BLOCKED = 'ip_blocked'
    CONFIG_CHANGE = 'config_change'
    SETTINGS_CHANGED = 'settings_changed'

if __name__ == '__main__':
    # Тестирование системы логирования
    print("Тестирование системы аудита...")
    
    # Создаем тестовые записи
    log_action(AuditActions.LOGIN, details={'test': True})
    log_action(AuditActions.CREATE_CLIENT, details={'client_name': 'test-client'})
    log_action(AuditActions.LOGIN_FAILED, status='error', error_message='Invalid password')
    
    # Получаем логи
    logs = get_audit_logs(limit=10)
    print(f"Найдено {len(logs)} записей в логе")
    
    # Получаем статистику
    stats = get_audit_stats()
    print(f"Статистика: {stats}")
    
    print("Тестирование завершено!")

