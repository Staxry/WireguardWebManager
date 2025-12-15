#!/usr/bin/env python3
"""
REST API для WireGuard Web Management Interface
"""

import json
import hashlib
import hmac
import time
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from flask import Blueprint, request, jsonify, current_app
from .audit_log import log_action, AuditActions
from .database import TrafficDB

# Создаем Blueprint для API
api_bp = Blueprint('api', __name__, url_prefix='/api/v1')

# Пути к данным
# Путь к корню проекта (на уровень выше пакета wg_web)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / 'data'
LOGS_DIR = PROJECT_ROOT / 'logs'
API_KEYS_FILE = DATA_DIR / 'api_keys.json'
ALERTS_FILE = LOGS_DIR / 'alerts.json'

# API ключи (в продакшене должны храниться в базе данных)
API_KEYS = {}

def load_api_keys():
    """Загрузка API ключей из файла"""
    global API_KEYS
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        if API_KEYS_FILE.exists():
            API_KEYS = json.loads(API_KEYS_FILE.read_text(encoding='utf-8'))
        else:
            # Создаем файл с дефолтным ключом
            default_key = generate_api_key()
            API_KEYS = {
                'default': {
                    'key': default_key,
                    'name': 'Default API Key',
                    'permissions': ['read', 'write'],
                    'created_at': datetime.now().isoformat(),
                    'last_used': None,
                    'usage_count': 0
                }
            }
            save_api_keys()
            print(f"Создан API ключ по умолчанию: {default_key}")
    except Exception as exc:
        print(f"Не удалось загрузить API ключи: {exc}")
        API_KEYS = {}

def save_api_keys():
    """Сохранение API ключей в файл"""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    API_KEYS_FILE.write_text(json.dumps(API_KEYS, indent=2, ensure_ascii=False), encoding='utf-8')

def generate_api_key():
    """Генерация нового API ключа"""
    import secrets
    return 'wg_' + secrets.token_urlsafe(32)

def verify_api_key(api_key):
    """Проверка API ключа"""
    for key_id, key_data in API_KEYS.items():
        if key_data['key'] == api_key:
            # Обновляем статистику использования
            key_data['last_used'] = datetime.now().isoformat()
            key_data['usage_count'] = key_data.get('usage_count', 0) + 1
            save_api_keys()
            return key_data
    return None

# ------------ Управление алертами для Dashboard ------------

def _load_alerts():
    """Загрузка алертов из файла (используется для Dashboard)."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    if not ALERTS_FILE.exists():
        ALERTS_FILE.write_text(json.dumps([], ensure_ascii=False, indent=2), encoding='utf-8')
        return []
    try:
        return json.loads(ALERTS_FILE.read_text(encoding='utf-8'))
    except Exception as exc:
        print(f"Не удалось загрузить alerts.json: {exc}")
        return []

def _save_alerts(alerts):
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    ALERTS_FILE.write_text(json.dumps(alerts, ensure_ascii=False, indent=2), encoding='utf-8')

def add_alert(title, message, severity='info', icon='ℹ️'):
    """Утилита для добавления нового алерта (может вызываться из других модулей)."""
    alerts = _load_alerts()
    alert_id = f"al_{int(time.time()*1000)}"
    alerts.append({
        'id': alert_id,
        'title': title,
        'message': message,
        'severity': severity,
        'icon': icon,
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'created_at': datetime.now().isoformat()
    })
    _save_alerts(alerts)
    log_action('create_alert', details={'id': alert_id, 'title': title, 'severity': severity})
    return alert_id

def api_auth_required(permissions=None):
    """Декоратор для проверки API аутентификации"""
    if permissions is None:
        permissions = ['read']
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Проверяем API ключ в заголовке
            api_key = request.headers.get('X-API-Key')
            if not api_key:
                log_action(AuditActions.LOGIN_FAILED, 
                          details={'reason': 'Missing API key', 'endpoint': request.endpoint},
                          status='error')
                return jsonify({'error': 'API key required'}), 401
            
            # Проверяем валидность ключа
            key_data = verify_api_key(api_key)
            if not key_data:
                log_action(AuditActions.LOGIN_FAILED,
                          details={'reason': 'Invalid API key', 'endpoint': request.endpoint},
                          status='error')
                return jsonify({'error': 'Invalid API key'}), 401
            
            # Проверяем права доступа
            user_permissions = key_data.get('permissions', [])
            if not any(perm in user_permissions for perm in permissions):
                log_action(AuditActions.LOGIN_FAILED,
                          details={'reason': 'Insufficient permissions', 'endpoint': request.endpoint},
                          status='error')
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            # Добавляем информацию о ключе в request
            request.api_key_data = key_data
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def rate_limit(max_requests=60, window=60):
    """Простой rate limiting для API"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Используем IP + API ключ для идентификации
            client_id = f"{request.remote_addr}_{request.headers.get('X-API-Key', 'unknown')}"
            
            # Проверяем rate limit (упрощенная реализация)
            # В продакшене лучше использовать Redis
            current_time = time.time()
            window_start = current_time - window
            
            # Здесь должна быть логика проверки rate limit
            # Для простоты пропускаем
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Импортируем функции из основного приложения
def get_clients_data():
    """Получение данных клиентов (импорт из app.py)"""
    try:
        import sys
        import importlib.util
        app_path = PROJECT_ROOT / 'app.py'
        if app_path.exists():
            spec = importlib.util.spec_from_file_location("app", str(app_path))
            app_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(app_module)
            return app_module.parse_wg_config()
        return []
    except Exception:
        return []

def create_client_api(client_name):
    """Создание клиента через API (импорт из app.py)"""
    try:
        import sys
        import importlib.util
        app_path = PROJECT_ROOT / 'app.py'
        if app_path.exists():
            spec = importlib.util.spec_from_file_location("app", str(app_path))
            app_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(app_module)
            return app_module.create_client_with_script(client_name)
        return False, "Import error"
    except Exception:
        return False, "Import error"

def delete_client_api(client_name):
    """Удаление клиента через API (импорт из app.py)"""
    try:
        import sys
        import importlib.util
        app_path = PROJECT_ROOT / 'app.py'
        if app_path.exists():
            spec = importlib.util.spec_from_file_location("app", str(app_path))
            app_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(app_module)
            return app_module.delete_client_from_server(client_name)
        return False, "Import error"
    except Exception:
        return False, "Import error"

# API Endpoints

@api_bp.route('/status', methods=['GET'])
def api_status():
    """Статус API"""
    return jsonify({
        'status': 'online',
        'version': '2.0',
        'timestamp': datetime.now().isoformat(),
        'endpoints': {
            'clients': '/api/v1/clients',
            'client': '/api/v1/clients/<name>',
            'stats': '/api/v1/stats',
            'logs': '/api/v1/logs'
        }
    })

@api_bp.route('/clients', methods=['GET'])
@api_auth_required(['read'])
@rate_limit(max_requests=100, window=60)
def api_get_clients():
    """Получение списка всех клиентов"""
    try:
        clients = get_clients_data()
        
        # Добавляем дополнительную информацию
        for client in clients:
            client['api_retrieved_at'] = datetime.now().isoformat()
        
        log_action(AuditActions.VIEW_CLIENTS, 
                  details={'api_endpoint': True, 'client_count': len(clients)})
        
        return jsonify({
            'status': 'success',
            'data': clients,
            'count': len(clients),
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        log_action(AuditActions.VIEW_CLIENTS,
                  status='error',
                  error_message=str(e))
        return jsonify({'error': str(e)}), 500

@api_bp.route('/clients/<client_name>', methods=['GET'])
@api_auth_required(['read'])
@rate_limit(max_requests=200, window=60)
def api_get_client(client_name):
    """Получение информации о конкретном клиенте"""
    try:
        clients = get_clients_data()
        client = next((c for c in clients if c['name'] == client_name), None)
        
        if not client:
            return jsonify({'error': 'Client not found'}), 404
        
        log_action(AuditActions.VIEW_CLIENTS,
                  details={'api_endpoint': True, 'client_name': client_name})
        
        return jsonify({
            'status': 'success',
            'data': client,
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        log_action(AuditActions.VIEW_CLIENTS,
                  status='error',
                  error_message=str(e))
        return jsonify({'error': str(e)}), 500

@api_bp.route('/clients', methods=['POST'])
@api_auth_required(['write'])
@rate_limit(max_requests=20, window=60)
def api_create_client():
    """Создание нового клиента"""
    try:
        data = request.get_json()
        if not data or 'name' not in data:
            return jsonify({'error': 'Client name is required'}), 400
        
        client_name = data['name']
        
        # Валидация имени клиента
        if not client_name.replace('-', '').replace('_', '').isalnum():
            return jsonify({'error': 'Invalid client name format'}), 400
        
        # Создаем клиента
        success, message = create_client_api(client_name)
        
        if success:
            log_action(AuditActions.CREATE_CLIENT,
                      details={'api_endpoint': True, 'client_name': client_name})
            
            return jsonify({
                'status': 'success',
                'message': f'Client {client_name} created successfully',
                'client_name': client_name,
                'timestamp': datetime.now().isoformat()
            }), 201
        else:
            log_action(AuditActions.CREATE_CLIENT,
                      status='error',
                      error_message=message,
                      details={'client_name': client_name})
            
            return jsonify({'error': message}), 400
    
    except Exception as e:
        log_action(AuditActions.CREATE_CLIENT,
                  status='error',
                  error_message=str(e))
        return jsonify({'error': str(e)}), 500

@api_bp.route('/clients/<client_name>', methods=['DELETE'])
@api_auth_required(['write'])
@rate_limit(max_requests=20, window=60)
def api_delete_client(client_name):
    """Удаление клиента"""
    try:
        success, message = delete_client_api(client_name)
        
        if success:
            log_action(AuditActions.DELETE_CLIENT,
                      details={'api_endpoint': True, 'client_name': client_name})
            
            return jsonify({
                'status': 'success',
                'message': f'Client {client_name} deleted successfully',
                'client_name': client_name,
                'timestamp': datetime.now().isoformat()
            })
        else:
            log_action(AuditActions.DELETE_CLIENT,
                      status='error',
                      error_message=message,
                      details={'client_name': client_name})
            
            return jsonify({'error': message}), 400
    
    except Exception as e:
        log_action(AuditActions.DELETE_CLIENT,
                  status='error',
                  error_message=str(e))
        return jsonify({'error': str(e)}), 500

@api_bp.route('/stats', methods=['GET'])
@api_auth_required(['read'])
@rate_limit(max_requests=50, window=60)
def api_get_stats():
    """Получение статистики сервера"""
    try:
        clients = get_clients_data()
        
        # Базовая статистика
        stats = {
            'total_clients': len(clients),
            'active_clients': len([c for c in clients if c.get('last_handshake')]),
            'server_status': 'online',
            'timestamp': datetime.now().isoformat()
        }
        
        # Статистика трафика
        total_received = sum(int(c.get('transfer_received', 0)) for c in clients)
        total_sent = sum(int(c.get('transfer_sent', 0)) for c in clients)
        
        stats['traffic'] = {
            'total_received_bytes': total_received,
            'total_sent_bytes': total_sent,
            'total_bytes': total_received + total_sent
        }
        
        # Топ клиентов по трафику (оперативный срез)
        clients_by_traffic = sorted(clients, 
                                  key=lambda x: int(x.get('transfer_received', 0)) + int(x.get('transfer_sent', 0)),
                                  reverse=True)
        
        stats['top_clients'] = [
            {
                'name': c['name'],
                'total_traffic': int(c.get('transfer_received', 0)) + int(c.get('transfer_sent', 0))
            }
            for c in clients_by_traffic[:5]
        ]
        
        return jsonify({
            'status': 'success',
            'data': stats
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/stats/traffic', methods=['GET'])
@api_auth_required(['read'])
@rate_limit(max_requests=60, window=60)
def api_stats_traffic():
    """Агрегированный трафик за период для графика"""
    rng = request.args.get('range', '24h')
    hours_map = {'1h': 1, '6h': 6, '24h': 24, '7d': 24*7, '30d': 24*30}
    hours = hours_map.get(rng, 24)

    rows = TrafficDB.get_traffic_history(hours=hours)

    from collections import defaultdict
    buckets_received = defaultdict(int)
    buckets_sent = defaultdict(int)

    def bucket_label(ts_str):
        # ts: 'YYYY-MM-DD HH:MM:SS'
        if rng.endswith('d'):
            return ts_str[:10]  # по дням
        return ts_str[:13]  # по часам

    for r in rows:
        ts = r['timestamp']
        label = bucket_label(ts)
        buckets_received[label] += int(r.get('bytes_received') or 0)
        buckets_sent[label] += int(r.get('bytes_sent') or 0)

    labels = sorted(set(buckets_received.keys()) | set(buckets_sent.keys()))

    def to_mb(x):
        return round(x / (1024*1024), 2)

    received = [to_mb(buckets_received.get(l, 0)) for l in labels]
    sent = [to_mb(buckets_sent.get(l, 0)) for l in labels]
    total = [round(received[i] + sent[i], 2) for i in range(len(labels))]

    return jsonify({'success': True, 'data': {'labels': labels, 'received': received, 'sent': sent, 'total': total}})

@api_bp.route('/logs', methods=['GET'])
@api_auth_required(['read'])
@rate_limit(max_requests=30, window=60)
def api_get_logs():
    """Получение логов аудита"""
    try:
        from .audit_log import get_audit_logs
        
        # Параметры запроса
        limit = min(int(request.args.get('limit', 50)), 200)  # Максимум 200
        action_filter = request.args.get('action')
        
        logs = get_audit_logs(limit=limit, filter_action=action_filter)
        
        return jsonify({
            'status': 'success',
            'data': logs,
            'count': len(logs),
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/alerts', methods=['GET'])
@api_auth_required(['read'])
def api_get_alerts():
    """Получение списка алертов для Dashboard."""
    try:
        alerts = _load_alerts()
        # Можно отфильтровать только актуальные, но пока возвращаем все
        return jsonify({'success': True, 'data': alerts})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/alerts/<alert_id>/dismiss', methods=['POST'])
@api_auth_required(['write'])
def api_dismiss_alert(alert_id):
    """Пометка алерта как прочитанного/удаленного."""
    try:
        alerts = _load_alerts()
        new_alerts = [a for a in alerts if a.get('id') != alert_id]
        _save_alerts(new_alerts)
        log_action('dismiss_alert', details={'id': alert_id})
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@api_bp.route('/keys', methods=['GET'])
@api_auth_required(['read'])
def api_list_keys():
    """Получение списка API ключей (без самих ключей)"""
    try:
        keys_info = []
        for key_id, key_data in API_KEYS.items():
            keys_info.append({
                'id': key_id,
                'name': key_data.get('name', 'Unknown'),
                'permissions': key_data.get('permissions', []),
                'created_at': key_data.get('created_at'),
                'last_used': key_data.get('last_used'),
                'usage_count': key_data.get('usage_count', 0)
            })
        
        return jsonify({
            'status': 'success',
            'data': keys_info
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/keys', methods=['POST'])
@api_auth_required(['write'])
def api_create_key():
    """Создание нового API ключа"""
    try:
        data = request.get_json()
        if not data or 'name' not in data:
            return jsonify({'error': 'Key name is required'}), 400
        
        key_name = data['name']
        permissions = data.get('permissions', ['read'])
        
        # Генерируем новый ключ
        new_key = generate_api_key()
        key_id = f"key_{int(time.time())}"
        
        API_KEYS[key_id] = {
            'key': new_key,
            'name': key_name,
            'permissions': permissions,
            'created_at': datetime.now().isoformat(),
            'last_used': None,
            'usage_count': 0
        }
        
        save_api_keys()
        
        log_action('create_api_key',
                  details={'key_name': key_name, 'permissions': permissions})
        
        return jsonify({
            'status': 'success',
            'message': 'API key created successfully',
            'key_id': key_id,
            'api_key': new_key,  # Показываем ключ только при создании
            'name': key_name,
            'permissions': permissions
        }), 201
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/keys/<key_id>', methods=['DELETE'])
@api_auth_required(['write'])
def api_delete_key(key_id):
    """Удаление API ключа по его идентификатору."""
    try:
        if key_id not in API_KEYS:
            return jsonify({'error': 'Key not found'}), 404

        key_info = API_KEYS.pop(key_id)
        save_api_keys()

        log_action('delete_api_key', details={'key_id': key_id, 'name': key_info.get('name')})

        return jsonify({'status': 'success', 'message': 'API key deleted', 'key_id': key_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Обработчики ошибок для API
@api_bp.errorhandler(404)
def api_not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@api_bp.errorhandler(405)
def api_method_not_allowed(error):
    return jsonify({'error': 'Method not allowed'}), 405

@api_bp.errorhandler(500)
def api_internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# Инициализация API
def init_api():
    """Инициализация API модуля"""
    load_api_keys()
    print("API модуль инициализирован")
    print(f"Доступные API ключи: {len(API_KEYS)}")

if __name__ == '__main__':
    # Тестирование API
    init_api()
    print("API ключи:", API_KEYS)

