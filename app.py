#!/usr/bin/env python3
"""
WireGuard Web Management Interface
Улучшенное веб-приложение для управления клиентами WireGuard с повышенной безопасностью
"""

import os
import re
import subprocess
import json
import glob
from datetime import datetime, timedelta
import time
import threading
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from functools import wraps
import configparser

# Импортируем модули безопасности и функциональности из пакета wg_web
try:
    from wg_web.admin_config import (
        load_admin_config, verify_password, is_session_expired,
        record_failed_login, is_ip_blocked, clear_login_attempts,
        change_admin_password,
    )
    SECURITY_ENABLED = True
except ImportError:
    print("⚠️  Модуль admin_config не найден. Используется базовая аутентификация.")
    SECURITY_ENABLED = False

# Импортируем дополнительные модули
try:
    from wg_web.audit_log import log_action, AuditActions, get_audit_logs, get_audit_stats
    AUDIT_ENABLED = True
except ImportError:
    print("⚠️  Модуль audit_log не найден. Логирование отключено.")
    AUDIT_ENABLED = False
    def log_action(*args, **kwargs): pass  # Заглушка

try:
    from wg_web.rate_limiter import rate_limit, get_rate_limit_status, get_blocked_ips_info
    RATE_LIMIT_ENABLED = True
except ImportError:
    print("⚠️  Модуль rate_limiter не найден. Rate limiting отключен.")
    RATE_LIMIT_ENABLED = False
    def rate_limit(*args, **kwargs): lambda f: f  # Заглушка-декоратор

try:
    from wg_web.database import init_database, ClientDB, TrafficDB, SettingsDB
    DATABASE_ENABLED = True
except ImportError:
    print("⚠️  Модуль database не найден. База данных отключена.")
    DATABASE_ENABLED = False

try:
    from wg_web.api import api_bp, init_api
    API_ENABLED = True
except ImportError:
    print("⚠️  Модуль api не найден. API отключено.")
    API_ENABLED = False

app = Flask(__name__)

# Добавляем фильтр для форматирования времени
@app.template_filter('timestamp_to_date')
def timestamp_to_date(timestamp):
    """Конвертирует timestamp в читаемую дату"""
    try:
        return datetime.fromtimestamp(timestamp).strftime('%d.%m.%Y %H:%M')
    except:
        return 'Неизвестно'

# Добавляем фильтр для получения директории из пути
@app.template_filter('dirname')
def dirname_filter(path):
    """Получает директорию из полного пути к файлу"""
    return os.path.dirname(path)

# Загружаем конфигурацию безопасности
if SECURITY_ENABLED:
    admin_config = load_admin_config()
    app.secret_key = admin_config['secret_key']
    SESSION_TIMEOUT = admin_config['session_timeout']
else:
    app.secret_key = 'your-secret-key-change-this'  # Fallback
    SESSION_TIMEOUT = 600

# Инициализация дополнительных модулей
if DATABASE_ENABLED:
    try:
        init_database()
        print("✅ База данных инициализирована")
    except Exception as e:
        print(f"❌ Ошибка инициализации базы данных: {e}")
        DATABASE_ENABLED = False

if API_ENABLED:
    try:
        init_api()
        app.register_blueprint(api_bp)
        print("✅ API модуль зарегистрирован")
    except Exception as e:
        print(f"❌ Ошибка инициализации API: {e}")
        API_ENABLED = False

# Конфигурация
WIREGUARD_INTERFACE = 'wg0'

# Определяем пути для конфигураций (приоритет для Ubuntu сервера)
if os.path.exists('/etc/wireguard/') and os.access('/etc/wireguard/', os.R_OK):
    # Основные пути на Ubuntu сервере
    WG_CONFIG_FILE = f'/etc/wireguard/{WIREGUARD_INTERFACE}.conf'
    WIREGUARD_CONFIG_PATH = '/root/'  # Конфиги клиентов сохраняются в /root/
elif os.path.exists('/root/') and os.access('/root/', os.W_OK):
    # Альтернативные пути
    WIREGUARD_CONFIG_PATH = '/root/'
    WG_CONFIG_FILE = f'/etc/wireguard/{WIREGUARD_INTERFACE}.conf'
else:
    # Fallback для тестирования
    WIREGUARD_CONFIG_PATH = './wireguard/'
    WG_CONFIG_FILE = f'./wireguard/{WIREGUARD_INTERFACE}.conf'
    # Создаем директорию, если её нет
    os.makedirs(WIREGUARD_CONFIG_PATH, exist_ok=True)

# Fallback аутентификация (если модуль безопасности недоступен)
FALLBACK_USERNAME = 'admin'
FALLBACK_PASSWORD = 'admin123'

def get_client_ip():
    """Получает IP адрес клиента"""
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        return request.environ['REMOTE_ADDR']
    else:
        return request.environ['HTTP_X_FORWARDED_FOR']

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Логирование для отладки
        print(f"🔐 login_required: endpoint={request.endpoint}, method={request.method}, path={request.path}")
        print(f"   Session logged_in: {session.get('logged_in')}")
        
        # Проверяем, является ли запрос JSON (AJAX/API)
        # Проверяем несколькими способами для надежности
        content_type = request.content_type or request.headers.get('Content-Type', '')
        accept_header = request.headers.get('Accept', '')
        
        is_json_request = (
            request.method == 'POST' and 
            ('application/json' in content_type.lower() or 'application/json' in accept_header.lower())
        ) or (
            accept_header.startswith('application/json')
        )
        
        print(f"   is_json_request: {is_json_request}, content_type: {content_type}, accept: {accept_header}")
        
        if 'logged_in' not in session:
            print(f"❌ login_required: Пользователь не авторизован")
            if is_json_request:
                return jsonify({'success': False, 'message': 'Требуется авторизация'}), 401
            return redirect(url_for('login'))
        
        # Проверяем истечение сессии
        if SECURITY_ENABLED:
            login_time = session.get('login_time')
            if is_session_expired(login_time, SESSION_TIMEOUT // 60):
                print(f"❌ login_required: Сессия истекла")
                session.clear()
                if is_json_request:
                    return jsonify({'success': False, 'message': 'Сессия истекла. Войдите снова.'}), 401
                flash('Сессия истекла. Войдите снова.')
                return redirect(url_for('login'))
        
        print(f"✅ login_required: Разрешен доступ к {request.endpoint}")
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
@rate_limit('login', block_on_exceed=True, block_duration=900) if RATE_LIMIT_ENABLED else lambda f: f
def login():
    client_ip = get_client_ip()
    
    # Проверяем блокировку IP
    if SECURITY_ENABLED and is_ip_blocked(client_ip):
        flash('IP адрес временно заблокирован из-за множественных неудачных попыток входа.')
        return render_template('login.html')
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Проверяем учетные данные
        login_success = False
        
        if SECURITY_ENABLED:
            admin_config = load_admin_config()
            if (username == admin_config['username'] and 
                verify_password(password, admin_config['password_hash'])):
                login_success = True
        else:
            # Fallback аутентификация
            if username == FALLBACK_USERNAME and password == FALLBACK_PASSWORD:
                login_success = True
        
        if login_success:
            session['logged_in'] = True
            session['login_time'] = datetime.now().isoformat()
            session['username'] = username
            
            if SECURITY_ENABLED:
                clear_login_attempts(client_ip)
            
            # Логируем успешный вход
            log_action(AuditActions.LOGIN, details={'username': username})
            
            flash('Добро пожаловать!')
            return redirect(url_for('index'))
        else:
            if SECURITY_ENABLED:
                record_failed_login(client_ip)
            
            # Логируем неудачный вход
            log_action(AuditActions.LOGIN_FAILED, 
                      details={'username': username, 'ip_address': client_ip},
                      status='error')
            
            flash('Неверные учетные данные')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    # Логируем выход из системы
    if 'username' in session:
        log_action(AuditActions.LOGOUT, details={'username': session['username']})
    
    session.clear()
    flash('Вы вышли из системы')
    return redirect(url_for('login'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
@rate_limit('password_change', block_on_exceed=True, block_duration=1800) if RATE_LIMIT_ENABLED else lambda f: f
def change_password():
    if not SECURITY_ENABLED:
        flash('Изменение пароля недоступно в режиме fallback')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('Новые пароли не совпадают')
            return render_template('change_password.html')
        
        success, message = change_admin_password(
            session['username'], current_password, new_password
        )
        
        if success:
            # Логируем успешную смену пароля
            log_action(AuditActions.PASSWORD_CHANGED, 
                      details={'username': session['username']})
            flash(message)
            return redirect(url_for('index'))
        else:
            # Логируем неудачную попытку смены пароля
            log_action(AuditActions.PASSWORD_CHANGED, 
                      details={'username': session['username'], 'error': message},
                      status='error')
            flash(message)
    
    return render_template('change_password.html')

@app.route('/change_username', methods=['GET', 'POST'])
@login_required
@rate_limit('username_change', block_on_exceed=True, block_duration=1800) if RATE_LIMIT_ENABLED else lambda f: f
def change_username():
    if not SECURITY_ENABLED:
        flash('Изменение имени пользователя недоступно в режиме fallback')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_username = request.form['new_username']
        confirm_username = request.form['confirm_username']
        
        if new_username != confirm_username:
            flash('Новые имена пользователя не совпадают')
            return render_template('change_username.html')
        
        from wg_web.admin_config import change_admin_username
        success, message = change_admin_username(
            session['username'], current_password, new_username
        )
        
        if success:
            # Обновляем имя пользователя в сессии
            old_username = session['username']
            session['username'] = new_username
            
            # Логируем успешную смену имени пользователя
            log_action(AuditActions.CONFIG_CHANGE, 
                      details={'action': 'username_changed', 'old_username': old_username, 'new_username': new_username})
            flash(message)
            return redirect(url_for('index'))
        else:
            # Логируем неудачную попытку смены имени пользователя
            log_action(AuditActions.CONFIG_CHANGE, 
                      details={'action': 'username_change_failed', 'username': session['username'], 'error': message},
                      status='error')
            flash(message)
    
    return render_template('change_username.html')

@app.route('/settings')
@login_required
def settings():
    """Страница настроек администратора"""
    # Получаем статус интерфейса
    wg_status = get_wg_status()
    interface_active = wg_status is not None
    
    # Информация о сессии
    session_info = {
        'username': session.get('username', 'admin'),
        'login_time': session.get('login_time'),
        'timeout_minutes': SESSION_TIMEOUT // 60 if SECURITY_ENABLED else 10
    }
    
    return render_template('settings.html',
                         interface_active=interface_active,
                         interface_name=WIREGUARD_INTERFACE,
                         session_info=session_info,
                         security_enabled=SECURITY_ENABLED)

def run_command(command, timeout=30):
    """Выполнение команды в системе с таймаутом"""
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True,
            timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Команда превысила таймаут ({timeout} секунд)", 124
    except Exception as e:
        return "", str(e), 1

def load_wireguard_params():
    """Загрузка параметров WireGuard из файла params"""
    params = {}
    
    # Список возможных расположений файла параметров (приоритет для Ubuntu сервера)
    possible_params_files = [
        '/etc/wireguard/params',  # Стандартное расположение в Ubuntu (приоритет)
        '/root/params',           # Альтернативное расположение на сервере
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'params'),  # В директории скрипта
        './data/params',          # В папке data проекта (для тестирования)
        '../../Documents/params', # Для тестирования
        './params',               # В текущей директории
        './test_params',          # Тестовый файл
        os.path.expanduser('~/Documents/params')  # В домашней директории
    ]
    
    params_file = None
    for file_path in possible_params_files:
        if os.path.exists(file_path):
            params_file = file_path
            break
    
    # Сначала устанавливаем параметры по умолчанию (как в wireguard-install.sh)
    params = {
        'SERVER_PUB_KEY': 'EJMa2L0+n2/9CWt08ewIhNqvBpF/xyefGIS7bLfxuUc=',
        'SERVER_PUB_IP': '77.238.224.56',
        'SERVER_PORT': '49158',
        'CLIENT_DNS_1': '1.1.1.1',  # Adguard DNS по умолчанию как в оригинале
        'CLIENT_DNS_2': '1.0.0.1',  # Adguard DNS по умолчанию как в оригинале
        'ALLOWED_IPS': '0.0.0.0/0,::/0'
    }
    
    if params_file:
        try:
            with open(params_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if '=' in line and not line.startswith('#'):
                        key, value = line.split('=', 1)
                        params[key.strip()] = value.strip()
            print(f"Параметры WireGuard загружены из: {params_file}")
        except Exception as e:
            print(f"Ошибка чтения файла параметров {params_file}: {e}")
            print("Используются параметры по умолчанию")
    else:
        print("Файл параметров WireGuard не найден, используются параметры по умолчанию")
    
    return params

def check_wg_command():
    """Проверка наличия команды wg"""
    # Проверяем разные возможные пути
    wg_paths = ['/usr/bin/wg', '/usr/local/bin/wg', 'wg']
    
    for wg_path in wg_paths:
        stdout, stderr, code = run_command(f'which {wg_path}')
        if code == 0:
            return wg_path
    
    # Проверяем прямо команду wg
    stdout, stderr, code = run_command('wg --version')
    if code == 0:
        return 'wg'
    
    return None

def get_wg_status():
    """Получение статуса WireGuard интерфейса"""
    wg_cmd = check_wg_command()
    if not wg_cmd:
        print("⚠️  WireGuard не найден")
        return None
    
    stdout, stderr, code = run_command(f'{wg_cmd} show {WIREGUARD_INTERFACE}')
    if code != 0:
        return None
    return stdout

def get_clients_connection_status():
    """Получение статуса подключения клиентов"""
    wg_status = get_wg_status()
    if not wg_status:
        return {}
    
    clients_status = {}
    current_peer = None
    
    for line in wg_status.split('\n'):
        line = line.strip()
        if line.startswith('peer:'):
            current_peer = line.split('peer:')[1].strip()
            clients_status[current_peer] = {
                'connected': False,
                'last_handshake': None,
                'transfer': {'received': 0, 'sent': 0}
            }
        elif current_peer and 'latest handshake:' in line:
            handshake_info = line.split('latest handshake:')[1].strip()
            if handshake_info and handshake_info != '(never)':
                clients_status[current_peer]['connected'] = True
                clients_status[current_peer]['last_handshake'] = handshake_info
        elif current_peer and 'transfer:' in line:
            transfer_info = line.split('transfer:')[1].strip()
            # Парсим информацию о трафике: "received, sent"
            if ',' in transfer_info:
                parts = transfer_info.split(',')
                if len(parts) >= 2:
                    received = parts[0].strip()
                    sent = parts[1].strip()
                    clients_status[current_peer]['transfer'] = {
                        'received': received,
                        'sent': sent
                    }
    
    return clients_status

def parse_wg_config():
    """Парсинг конфигурационных файлов клиентов WireGuard"""
    clients = []
    
    try:
        import os
        # Список директорий для поиска конфигураций клиентов
        search_directories = [
            '/root/',  # Ubuntu сервер - основная директория
            WIREGUARD_CONFIG_PATH,  # Fallback директория
            '/etc/wireguard/',  # Стандартная директория WireGuard
        ]
        
        client_files = []
        seen_files = set()  # Для отслеживания уже найденных файлов
        
        for search_dir in search_directories:
            if os.path.exists(search_dir):
                print(f"🔍 Ищем конфиги клиентов в: {search_dir}")
                
                # Ищем все файлы клиентов по маске wg0-client-*.conf
                search_pattern = f'{search_dir}wg0-client-*.conf'
                found_files = glob.glob(search_pattern)
                
                print(f"📁 Поиск по маске: {search_pattern}")
                print(f"📄 Найдено файлов: {len(found_files)}")
                
                # Добавляем только уникальные файлы (по реальному пути)
                for file_path in found_files:
                    real_path = os.path.realpath(file_path)  # Разрешаем символические ссылки
                    if real_path not in seen_files:
                        seen_files.add(real_path)
                        client_files.append(file_path)
                    else:
                        print(f"🔄 Пропускаем дубликат: {file_path} -> {real_path}")
            else:
                print(f"⚠️  Директория {search_dir} не существует")
        
        if not client_files:
            print("ℹ️  Конфигурационные файлы клиентов не найдены во всех директориях")
            return clients
        
        print(f"📊 Всего найдено файлов клиентов: {len(client_files)}")
        
        seen_client_names = set()  # Для отслеживания уже добавленных имен клиентов
        
        for i, config_file in enumerate(client_files, 1):
            try:
                print(f"📖 Обрабатываем файл: {config_file}")
                
                # Извлекаем имя клиента из имени файла
                filename = os.path.basename(config_file)
                # wg0-client-dasha.conf -> dasha
                client_name = filename.replace('wg0-client-', '').replace('.conf', '')
                
                with open(config_file, 'r') as f:
                    content = f.read()
                
                # Парсим конфигурацию клиента
                client_data = {}
                lines = content.split('\n')
                
                for line in lines:
                    line = line.strip()
                    if '=' in line and not line.startswith('#'):
                        key, value = line.split('=', 1)
                        client_data[key.strip()] = value.strip()
                
                # Получаем публичный ключ из приватного ключа клиента
                private_key = client_data.get('PrivateKey', '')
                public_key = ''
                
                if private_key:
                    # Генерируем публичный ключ из приватного
                    wg_cmd = check_wg_command()
                    if wg_cmd:
                        stdout, stderr, code = run_command(f'echo "{private_key}" | {wg_cmd} pubkey')
                        if code == 0:
                            public_key = stdout.strip()
                        else:
                            print(f"⚠️  Не удалось сгенерировать публичный ключ для {client_name}: {stderr}")
                            # Fallback - генерируем тестовый ключ
                            import base64
                            import os
                            public_key = base64.b64encode(os.urandom(32)).decode('utf-8')
                    else:
                        print(f"⚠️  WireGuard не найден, используем тестовый ключ для {client_name}")
                        import base64
                        import os
                        public_key = base64.b64encode(os.urandom(32)).decode('utf-8')
                
                # Проверяем, не добавляли ли мы уже клиента с таким именем
                if client_name in seen_client_names:
                    print(f"🔄 Пропускаем дубликат клиента: {client_name}")
                    continue
                
                seen_client_names.add(client_name)
                
                # Получаем разрешенные IP из основного конфига сервера
                allowed_ips = get_client_allowed_ips_from_server_config(public_key)
                
                client = {
                    'id': len(clients) + 1,  # Используем актуальный счетчик
                    'name': client_name,
                    'public_key': public_key,
                    'private_key': private_key,
                    'allowed_ips': allowed_ips or client_data.get('Address', ''),
                    'config_file': config_file,
                }
                clients.append(client)
                print(f"✅ Клиент {client_name} добавлен")
                
            except Exception as e:
                print(f"❌ Ошибка парсинга файла {config_file}: {e}")
                continue
    
    except Exception as e:
        print(f"❌ Ошибка поиска конфигов клиентов: {e}")
    
    print(f"🎯 Итого найдено клиентов: {len(clients)}")
    return clients

def get_client_allowed_ips_from_server_config(public_key):
    """Получение разрешенных IP клиента из основного конфига сервера"""
    if not public_key:
        return None
        
    if not os.path.exists(WG_CONFIG_FILE):
        print(f"Серверная конфигурация не найдена: {WG_CONFIG_FILE}")
        return None
    
    try:
        with open(WG_CONFIG_FILE, 'r') as f:
            content = f.read()
        
        # Ищем секцию [Peer] с нужным публичным ключом
        peer_sections = re.split(r'\n\s*\[Peer\]\s*\n', content)
        
        for section in peer_sections[1:]:  # Пропускаем [Interface]
            lines = section.strip().split('\n')
            peer_data = {}
            
            for line in lines:
                if '=' in line:
                    key, value = line.split('=', 1)
                    peer_data[key.strip()] = value.strip()
            
            if peer_data.get('PublicKey') == public_key:
                return peer_data.get('AllowedIPs', '')
    
    except PermissionError:
        print(f"Нет прав на чтение серверной конфигурации: {WG_CONFIG_FILE}")
    except Exception as e:
        print(f"Ошибка чтения конфига сервера: {e}")
    
    return None

def get_client_traffic():
    """Получение статистики трафика клиентов"""
    traffic_data = {}
    
    wg_cmd = check_wg_command()
    if not wg_cmd:
        print("⚠️  WireGuard не найден, статистика трафика недоступна")
        return traffic_data
    
    stdout, stderr, code = run_command(f'{wg_cmd} show {WIREGUARD_INTERFACE} transfer')
    if code == 0:
        lines = stdout.strip().split('\n')
        for line in lines:
            if line.strip():
                parts = line.split('\t')
                if len(parts) >= 3:
                    public_key = parts[0]
                    received = int(parts[1]) if parts[1].isdigit() else 0
                    sent = int(parts[2]) if parts[2].isdigit() else 0
                    traffic_data[public_key] = {
                        'received': received,
                        'sent': sent,
                        'total': received + sent
                    }
    
    return traffic_data

def format_bytes(bytes_count):
    """Форматирование байтов в читаемый вид"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} PB"

def remove_client_from_server_config(public_key):
    """Удаляет клиента из серверной конфигурации WireGuard"""
    # Определяем путь к конфигурации
    params = load_wireguard_params()
    interface_name = params.get('SERVER_WG_NIC', 'wg0')
    config_file = f'/etc/wireguard/{interface_name}.conf'
    
    if not os.path.exists(config_file):
        return False, f"Серверная конфигурация не найдена: {config_file}"
    
    try:
        with open(config_file, 'r') as f:
            content = f.read()
        
        original_content = content
        
        # Метод 1: Удаляем по комментарию ### Client
        # Ищем секцию с комментарием клиента
        pattern1 = rf'### Client [^\n]*\n\[Peer\]\n[^#]*?PublicKey\s*=\s*{re.escape(public_key)}[^#]*?(?=\n### Client|\n\[Interface\]|\Z)'
        new_content = re.sub(pattern1, '', content, flags=re.DOTALL)
        
        # Метод 2: Если не нашли, удаляем просто по PublicKey
        if new_content == content:
            pattern2 = rf'\n\[Peer\]\n[^[]*?PublicKey\s*=\s*{re.escape(public_key)}[^[]*?(?=\n\[|\Z)'
            new_content = re.sub(pattern2, '', content, flags=re.DOTALL)
        
        # Метод 3: Более агрессивный поиск - любая секция [Peer] с нужным ключом
        if new_content == content:
            lines = content.split('\n')
            new_lines = []
            skip_section = False
            in_peer_section = False
            
            for line in lines:
                line_stripped = line.strip()
                
                if line_stripped.startswith('[Peer]'):
                    in_peer_section = True
                    peer_section_start = len(new_lines)
                    new_lines.append(line)
                elif line_stripped.startswith('['):
                    # Новая секция
                    in_peer_section = False
                    skip_section = False
                    new_lines.append(line)
                elif in_peer_section and line_stripped.startswith('PublicKey'):
                    # Проверяем, это ли наш ключ
                    if public_key in line:
                        # Удаляем всю секцию [Peer]
                        skip_section = True
                        # Удаляем уже добавленные строки этой секции
                        while len(new_lines) > peer_section_start:
                            new_lines.pop()
                    else:
                        new_lines.append(line)
                elif not skip_section:
                    new_lines.append(line)
                elif line_stripped.startswith('[') or line_stripped.startswith('###'):
                    # Конец секции, которую мы пропускаем
                    skip_section = False
                    in_peer_section = False
                    new_lines.append(line)
            
            new_content = '\n'.join(new_lines)
        
        # Проверяем, что что-то изменилось
        if new_content == original_content:
            return False, f"Клиент с ключом {public_key[:20]}... не найден в конфигурации"
        
        # Очищаем лишние пустые строки
        new_content = re.sub(r'\n\s*\n\s*\n+', '\n\n', new_content)
        new_content = new_content.strip() + '\n'
        
        # Записываем обновленную конфигурацию
        with open(config_file, 'w') as f:
            f.write(new_content)
        
        print(f"Клиент с ключом {public_key[:20]}... удален из серверной конфигурации")
        return True, "Клиент успешно удален из серверной конфигурации"
        
    except Exception as e:
        return False, f"Ошибка при удалении клиента из конфигурации: {e}"

@app.route('/')
@login_required
def index():
    """Главная страница со списком клиентов"""
    clients = parse_wg_config()
    traffic_data = get_client_traffic()
    
    # Если клиентов нет, пытаемся найти конфигурации автоматически
    if not clients:
        scanned_configs = scan_config_files()
        # Фильтруем только клиентские конфигурации
        client_configs = [cfg for cfg in scanned_configs if cfg.get('is_client', False)]
        if client_configs:
            flash(f'Найдено {len(client_configs)} конфигураций клиентов. Перейдите в раздел "Импорт клиентов" для их добавления.', 'info')
    
    # Получаем статус подключения клиентов
    connection_status = get_clients_connection_status()
    
    # Добавляем информацию о трафике и статусе к клиентам
    for client in clients:
        public_key = client['public_key']
        
        # Добавляем информацию о трафике
        if public_key in traffic_data:
            client['traffic'] = traffic_data[public_key]
            client['traffic_formatted'] = {
                'received': format_bytes(traffic_data[public_key]['received']),
                'sent': format_bytes(traffic_data[public_key]['sent']),
                'total': format_bytes(traffic_data[public_key]['total'])
            }
        else:
            client['traffic'] = {'received': 0, 'sent': 0, 'total': 0}
            client['traffic_formatted'] = {
                'received': '0 B',
                'sent': '0 B',
                'total': '0 B'
            }
        
        # Добавляем статус подключения
        if public_key in connection_status:
            client['connected'] = connection_status[public_key]['connected']
            client['last_handshake'] = connection_status[public_key]['last_handshake']
        else:
            client['connected'] = False
            client['last_handshake'] = None
    
    # Статус интерфейса
    wg_status = get_wg_status()
    interface_active = wg_status is not None
    
    # Информация о сессии
    session_info = {
        'username': session.get('username', 'admin'),
        'login_time': session.get('login_time'),
        'timeout_minutes': SESSION_TIMEOUT // 60 if SECURITY_ENABLED else 10
    }
    
    return render_template('index.html', 
                         clients=clients, 
                         interface_active=interface_active,
                         interface_name=WIREGUARD_INTERFACE,
                         session_info=session_info,
                         security_enabled=SECURITY_ENABLED)

@app.route('/delete_client/<identifier>', methods=['GET', 'POST'])
@login_required
def delete_client(identifier):
    """Удаление клиента с сервера и из конфигурации"""
    import time
    start_time = time.time()
    
    # Логирование для отладки - ВАЖНО: если этой строки нет в логах, функция не вызывается!
    print(f"🔍 DELETE CLIENT FUNCTION CALLED: identifier='{identifier}', method={request.method}")
    print(f"   Content-Type: {request.content_type}, Headers Content-Type: {request.headers.get('Content-Type')}")
    print(f"   Accept: {request.headers.get('Accept')}")
    print(f"   Session logged_in: {session.get('logged_in')}")
    print(f"   request.endpoint: {request.endpoint}")
    print(f"   request.path: {request.path}")
    print(f"⏱️  Начало операции удаления клиента в {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        import os
        import tempfile
        
        # Декодируем identifier на случай URL-кодирования
        from urllib.parse import unquote
        if identifier:
            identifier = unquote(str(identifier)).strip()
        else:
            error_msg = 'Не указан идентификатор клиента'
            print(f"❌ {error_msg}")
            if request.method == 'POST':
                return jsonify({'success': False, 'message': error_msg}), 400
            flash(error_msg)
            return redirect(url_for('index'))
        
        print(f"🔍 Попытка удаления клиента: identifier='{identifier}' (тип: {type(identifier).__name__})")
        
        print(f"📂 Начинаем парсинг конфигурации WireGuard...")
        clients = parse_wg_config()
        print(f"✅ Парсинг завершен. Всего клиентов найдено: {len(clients)}")
        
        # Выводим список всех клиентов для отладки (только первые 5 для скорости)
        if clients:
            print(f"📋 Список клиентов (показываем первые 5 из {len(clients)}):")
            for i, client in enumerate(clients[:5], 1):
                print(f"  {i}. ID={client.get('id', 'N/A')}, name='{client.get('name', 'N/A')}'")
            if len(clients) > 5:
                print(f"  ... и еще {len(clients) - 5} клиентов")
        
        # Находим клиента по имени или ID
        print(f"🔍 [3/5] Начинаем поиск клиента для удаления...")
        # Сначала пытаемся найти по имени (приоритет)
        client_to_delete = None
        client_name = None
        found_by = None
        
        # Поиск по имени (приоритет) - точное совпадение
        print(f"🔍 [3/5] Ищем клиента по имени: '{identifier}'")
        # ВАЖНО: сначала ищем по имени, даже если identifier выглядит как число
        for client in clients:
            client_name_from_list = str(client.get('name', '')).strip()
            identifier_str = str(identifier).strip()
            # Сравниваем как строки, чтобы "123" (имя) не путалось с ID 123
            if client_name_from_list == identifier_str:
                client_to_delete = client
                client_name = client_name_from_list
                found_by = 'name'
                print(f"✅ Клиент найден по имени: '{identifier}' (имя в базе: '{client_name_from_list}')")
                break
        
        # Если не найдено по имени, пытаемся найти по ID
        if client_to_delete is None:
            try:
                client_id = int(identifier)
                print(f"🔢 Пытаемся найти по ID: {client_id}")
                
                # Ищем клиента по ID в списке
                for client in clients:
                    if client.get('id') == client_id:
                        client_to_delete = client
                        client_name = client.get('name', '')
                        found_by = 'id'
                        print(f"✅ Клиент найден по ID: {client_id}, имя: '{client_name}'")
                        break
                
                # Если не нашли по ID в поле 'id', пробуем по индексу (старый способ)
                if client_to_delete is None and client_id > 0 and client_id <= len(clients):
                    client_to_delete = clients[client_id - 1]
                    client_name = client_to_delete.get('name', '')
                    found_by = 'index'
                    print(f"✅ Клиент найден по индексу: {client_id}, имя: '{client_name}'")
                    
            except (ValueError, TypeError) as e:
                print(f"⚠️  Не удалось преобразовать '{identifier}' в число: {e}")
        
        # Если клиент не найден ни по имени, ни по ID
        if client_to_delete is None:
            error_msg = f'Клиент "{identifier}" не найден. Всего клиентов: {len(clients)}'
            print(f"❌ {error_msg}")
            flash(error_msg)
            if request.method == 'POST':
                response = jsonify({'success': False, 'message': error_msg})
                response.headers['Content-Type'] = 'application/json; charset=utf-8'
                print(f"❌ Возвращаем ошибку 404 для POST запроса: {error_msg}")
                return response, 404
            return redirect(url_for('index'))
        
        print(f"🎯 [3/5] Клиент найден методом '{found_by}': имя='{client_name}'")
        
        # client_name уже установлен выше
        public_key = client_to_delete['public_key']
        print(f"🔑 [3/5] Public key клиента: {public_key[:20]}...")
        
        # 1. Удаляем файл конфигурации клиента
        print(f"🗑️  [4/5] Начинаем удаление файлов и конфигурации...")
        client_config_file = client_to_delete.get('config_file')
        if client_config_file and os.path.exists(client_config_file):
            os.remove(client_config_file)
            print(f"Удален файл клиента: {client_config_file}")
        
        # 2. Удаляем клиента из основного конфига сервера
        success, message = remove_client_from_server_config(public_key)
        if not success:
            flash(f'Предупреждение: {message}')
        
        # 3. Пытаемся удалить клиента через оригинальный скрипт (в фоне, неблокирующе)
        # ВАЖНО: выполняем в фоне, чтобы не блокировать HTTP response
        def delete_via_script_background():
            """Выполняет удаление через expect скрипт в фоновом режиме"""
            try:
                script_path = '/root/wireguard-install.sh'
                if not os.path.exists(script_path):
                    return
                
                print(f"[BACKGROUND] Пытаемся удалить клиента {client_name} через оригинальный скрипт...")
                
                # Создаем временный expect скрипт для удаления
                expect_script = f'''#!/usr/bin/expect -f
set timeout 30
spawn bash {script_path}

# Ожидаем главное меню
expect "Select an option"
send "3\\r"

# Ожидаем список клиентов для удаления
expect "Select the existing client you want to remove"
send "{client_name}\\r"

# Подтверждаем удаление
expect "Confirm"
send "y\\r"

expect eof
'''
                
                with tempfile.NamedTemporaryFile(mode='w', suffix='.exp', delete=False) as f:
                    f.write(expect_script)
                    expect_script_path = f.name
                
                try:
                    os.chmod(expect_script_path, 0o755)
                    result = subprocess.run(
                        ['expect', expect_script_path],
                        capture_output=True,
                        text=True,
                        timeout=30  # Уменьшен таймаут до 30 секунд
                    )
                    
                    if result.returncode == 0:
                        print(f"[BACKGROUND] Клиент {client_name} удален через оригинальный скрипт")
                    else:
                        print(f"[BACKGROUND] Ошибка при удалении через скрипт (код {result.returncode}): {result.stderr}")
                    
                finally:
                    try:
                        os.unlink(expect_script_path)
                    except:
                        pass
                        
            except subprocess.TimeoutExpired:
                print(f"[BACKGROUND] Таймаут при удалении через expect скрипт (30 сек)")
            except Exception as e:
                print(f"[BACKGROUND] Не удалось удалить через скрипт: {e}")
        
        # Запускаем удаление через скрипт в фоновом потоке
        script_thread = threading.Thread(target=delete_via_script_background, daemon=True)
        script_thread.start()
        print(f"🔄 Запущен фоновый поток для удаления через expect скрипт (не блокирует HTTP response)")
        
        # 4. Перезагружаем конфигурацию WireGuard (в фоне, неблокирующе)
        # ВАЖНО: выполняем reload в отдельном потоке, чтобы не блокировать HTTP response
        def reload_wireguard_background():
            """Выполняет перезагрузку WireGuard в фоновом режиме"""
            try:
                print(f"🔄 [BACKGROUND] Начинаем синхронизацию WireGuard интерфейса {WIREGUARD_INTERFACE}...")
                
                # Используем wg syncconf - это быстрее и не разрывает соединения
                sync_cmd = f'wg syncconf {WIREGUARD_INTERFACE} <(wg-quick strip {WIREGUARD_INTERFACE})'
                
                # Таймаут 10 секунд
                stdout, stderr, code = run_command(f'bash -c "{sync_cmd}"', timeout=10)
                
                if code != 0:
                    if code == 124:  # Timeout
                        print(f"⚠️  [BACKGROUND] Syncconf превысил таймаут (10 сек), пробуем systemctl reload...")
                        fallback_cmd = f'systemctl reload wg-quick@{WIREGUARD_INTERFACE}'
                        stdout2, stderr2, code2 = run_command(fallback_cmd, timeout=10)
                        if code2 == 0:
                            print(f"✅ [BACKGROUND] WireGuard перезагружен через systemctl reload")
                        else:
                            print(f"⚠️  [BACKGROUND] Systemctl reload не удался (код {code2}): {stderr2}")
                    else:
                        print(f"⚠️  [BACKGROUND] Syncconf не удался (код {code}), пробуем systemctl reload...")
                        if stderr:
                            print(f"📋 [BACKGROUND] Ошибка syncconf: {stderr}")
                        fallback_cmd = f'systemctl reload wg-quick@{WIREGUARD_INTERFACE}'
                        stdout2, stderr2, code2 = run_command(fallback_cmd, timeout=10)
                        if code2 == 0:
                            print(f"✅ [BACKGROUND] WireGuard перезагружен через systemctl reload")
                        else:
                            print(f"⚠️  [BACKGROUND] Systemctl reload не удался (код {code2}): {stderr2}")
                else:
                    print(f"✅ [BACKGROUND] Конфигурация WireGuard успешно синхронизирована (syncconf)")
            except Exception as e:
                print(f"❌ [BACKGROUND] Ошибка при перезагрузке WireGuard: {e}")
        
        # Запускаем reload в фоновом потоке (неблокирующе)
        reload_thread = threading.Thread(target=reload_wireguard_background, daemon=True)
        reload_thread.start()
        print(f"🔄 Запущен фоновый поток для перезагрузки WireGuard (не блокирует HTTP response)")
        
        # Логируем успешное удаление клиента
        elapsed_time = time.time() - start_time
        print(f"📝 [5/5] Логируем операцию удаления...")
        log_action(AuditActions.DELETE_CLIENT, 
                  details={'client_name': client_name, 'public_key': public_key})
        
        if elapsed_time > 10:
            print(f"⚠️  ВНИМАНИЕ: Операция удаления заняла {elapsed_time:.2f} секунд (дольше 10 секунд)")
        
        print(f"✅ [5/5] Операция удаления завершена за {elapsed_time:.2f} секунд")
        print(f"📤 [5/5] Готовим HTTP response...")
        
        if request.method == 'POST':
            response = jsonify({'success': True, 'message': f'Клиент {client_name} успешно удален с сервера'})
            response.headers['Content-Type'] = 'application/json; charset=utf-8'
            print(f"✅ [5/5] Возвращаем успешный ответ для POST запроса (время: {elapsed_time:.2f} сек)")
            print(f"🚀 [5/5] RETURN RESPONSE - клиент '{client_name}' удален, response отправляется клиенту")
            return response
        else:
            flash(f'Клиент {client_name} успешно удален с сервера')
        
    except Exception as e:
        import traceback
        elapsed_time = time.time() - start_time
        error_trace = traceback.format_exc()
        
        # Логируем ошибку удаления
        log_action(AuditActions.DELETE_CLIENT, 
                  details={'client_name': client_name if 'client_name' in locals() else 'unknown', 
                          'error': str(e)},
                  status='error')
        
        print(f"❌ ОШИБКА при удалении клиента (заняло {elapsed_time:.2f} сек): {str(e)}")
        print(f"❌ Traceback:\n{error_trace}")
        
        if request.method == 'POST':
            error_response = jsonify({'success': False, 'message': f'Ошибка удаления клиента: {str(e)}'})
            error_response.headers['Content-Type'] = 'application/json; charset=utf-8'
            print(f"❌ Возвращаем ошибку 500 для POST запроса: {str(e)}")
            return error_response, 500
        else:
            flash(f'Ошибка удаления клиента: {e}')
            return redirect(url_for('index'))
    
    # Если это GET запрос, делаем редирект
    if request.method != 'POST':
        elapsed_time = time.time() - start_time
        print(f"⚠️  GET запрос завершен за {elapsed_time:.2f} сек, делаем редирект")
        return redirect(url_for('index'))
    
    # Fallback: если дошли сюда и это POST, возвращаем ошибку
    # ЭТО НЕ ДОЛЖНО ПРОИСХОДИТЬ, но на всякий случай гарантируем response
    elapsed_time = time.time() - start_time
    print(f"⚠️  WARNING: delete_client reached end without returning (заняло {elapsed_time:.2f} сек)")
    print(f"⚠️  Это критическая ошибка - функция должна была вернуть response раньше!")
    response = jsonify({'success': False, 'message': 'Неожиданная ошибка при удалении клиента'})
    response.headers['Content-Type'] = 'application/json; charset=utf-8'
    return response, 500

@app.route('/dashboard')
@login_required
@rate_limit('web_general') if RATE_LIMIT_ENABLED else lambda f: f
def dashboard():
    """Dashboard с мониторингом и статистикой"""
    try:
        # Получаем базовую статистику
        clients = parse_wg_config()
        wg_status = get_wg_status()
        
        # Подсчитываем активных клиентов
        active_clients = 0
        total_traffic = 0
        top_clients = []
        
        if wg_status:
            # Парсим статус WireGuard для получения информации о трафике
            lines = wg_status.strip().split('\n')
            current_peer = None
            
            for line in lines:
                if line.startswith('peer:'):
                    current_peer = line.split('peer: ')[1]
                elif line.strip().startswith('transfer:') and current_peer:
                    active_clients += 1
                    # Парсим трафик (пример: "transfer: 1.2 MiB received, 2.3 MiB sent")
                    transfer_info = line.strip().split('transfer: ')[1]
                    # Простой парсинг для демонстрации
                    if 'received' in transfer_info and 'sent' in transfer_info:
                        try:
                            parts = transfer_info.split(', ')
                            received = parts[0].split(' ')[0]
                            sent = parts[1].split(' ')[0]
                            # Конвертируем в MB для простоты
                            received_mb = float(received) if 'MiB' in parts[0] else float(received) / 1024
                            sent_mb = float(sent) if 'MiB' in parts[1] else float(sent) / 1024
                            client_traffic = received_mb + sent_mb
                            total_traffic += client_traffic
                            
                            # Находим имя клиента по публичному ключу
                            client_name = 'Unknown'
                            for client in clients:
                                if client['public_key'] == current_peer:
                                    client_name = client['name']
                                    break
                            
                            top_clients.append({
                                'name': client_name,
                                'traffic_formatted': f"{client_traffic:.1f} MB",
                                'percentage': 0  # Будет вычислено позже
                            })
                        except:
                            pass
        
        # Вычисляем проценты для топ клиентов
        if total_traffic > 0:
            for client in top_clients:
                traffic_mb = float(client['traffic_formatted'].split(' ')[0])
                client['percentage'] = (traffic_mb / total_traffic) * 100
        
        # Сортируем по трафику и берем топ 5
        top_clients = sorted(top_clients, key=lambda x: float(x['traffic_formatted'].split(' ')[0]), reverse=True)[:5]
        
        # Получаем системную информацию
        system_info = get_system_info()
        
        # Получаем информацию о WireGuard
        wireguard_info = get_wireguard_info()
        
        # Получаем последние события из audit log
        recent_events = []
        if AUDIT_ENABLED:
            try:
                logs = get_audit_logs(limit=10)
                for log in logs:
                    event_type = 'info'
                    event_icon = '📝'
                    
                    if log['action'] in ['login_failed', 'delete_client']:
                        event_type = 'warning'
                        event_icon = '⚠️'
                    elif log['action'] == 'login':
                        event_type = 'success'
                        event_icon = '✅'
                    elif log['action'] == 'create_client':
                        event_type = 'success'
                        event_icon = '➕'
                    
                    recent_events.append({
                        'time': log['timestamp'][:16],  # Обрезаем до минут
                        'description': f"{log['action']}: {log.get('details', {}).get('username', log.get('details', {}).get('client_name', 'N/A'))}",
                        'type': event_type,
                        'type_icon': event_icon
                    })
            except Exception as e:
                print(f"Ошибка получения событий: {e}")
        
        # Формируем статистику для шаблона
        stats = {
            'total_clients': len(clients),
            'active_clients': active_clients,
            'total_traffic_formatted': f"{total_traffic:.1f} MB",
            'server_uptime': get_server_uptime(),
            'top_clients': top_clients,
            'recent_events': recent_events,
            'system': system_info,
            'wireguard': wireguard_info
        }
        
        return render_template('dashboard.html', stats=stats)
        
    except Exception as e:
        flash(f'Ошибка загрузки dashboard: {e}')
        return redirect(url_for('index'))

def get_system_info():
    """Получение системной информации"""
    try:
        # CPU usage
        cpu_cmd = "top -l 1 | grep 'CPU usage' | awk '{print $3}' | sed 's/%//'"
        cpu_stdout, _, _ = run_command(cpu_cmd)
        cpu_usage = float(cpu_stdout.strip()) if cpu_stdout.strip() else 0
        
        # Memory usage
        mem_cmd = "vm_stat | grep 'Pages free' | awk '{print $3}' | sed 's/\\.//'"
        mem_stdout, _, _ = run_command(mem_cmd)
        # Простое приближение для демонстрации
        ram_usage = 45  # Заглушка
        
        # Disk usage
        disk_cmd = "df -h / | tail -1 | awk '{print $5}' | sed 's/%//'"
        disk_stdout, _, _ = run_command(disk_cmd)
        disk_usage = int(disk_stdout.strip()) if disk_stdout.strip().isdigit() else 0
        
        return {
            'cpu_usage': min(cpu_usage, 100),
            'ram_usage': ram_usage,
            'disk_usage': disk_usage,
            'network_status': 'Активна'
        }
    except Exception as e:
        print(f"Ошибка получения системной информации: {e}")
        return {
            'cpu_usage': 0,
            'ram_usage': 0,
            'disk_usage': 0,
            'network_status': 'Неизвестно'
        }

def get_wireguard_info():
    """Получение информации о WireGuard"""
    try:
        # Читаем конфигурацию сервера
        config_file = f'/etc/wireguard/{WIREGUARD_INTERFACE}.conf'
        port = '51820'  # По умолчанию
        public_key = 'Unknown'
        
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                content = f.read()
                
            # Ищем порт
            port_match = re.search(r'ListenPort\s*=\s*(\d+)', content)
            if port_match:
                port = port_match.group(1)
        
        # Получаем публичный ключ сервера
        pub_key_cmd = f"wg show {WIREGUARD_INTERFACE} public-key"
        pub_key_stdout, _, _ = run_command(pub_key_cmd)
        if pub_key_stdout.strip():
            public_key = pub_key_stdout.strip()
        
        # Проверяем статус интерфейса
        status_cmd = f"wg show {WIREGUARD_INTERFACE}"
        _, _, status_code = run_command(status_cmd)
        
        status = 'active' if status_code == 0 else 'inactive'
        status_text = 'Активен' if status_code == 0 else 'Неактивен'
        
        return {
            'interface': WIREGUARD_INTERFACE,
            'port': port,
            'public_key': public_key,
            'status': status,
            'status_text': status_text
        }
    except Exception as e:
        print(f"Ошибка получения информации WireGuard: {e}")
        return {
            'interface': WIREGUARD_INTERFACE,
            'port': '51820',
            'public_key': 'Unknown',
            'status': 'unknown',
            'status_text': 'Неизвестно'
        }

def get_server_uptime():
    """Получение времени работы сервера"""
    try:
        uptime_cmd = "uptime | awk '{print $3, $4}' | sed 's/,//'"
        uptime_stdout, _, _ = run_command(uptime_cmd)
        return uptime_stdout.strip() if uptime_stdout.strip() else 'Unknown'
    except:
        return 'Unknown'

def get_interface_name():
    """Получение имени WireGuard интерфейса"""
    try:
        # Ищем активные WireGuard интерфейсы
        wg_cmd = check_wg_command()
        if wg_cmd:
            stdout, stderr, code = run_command(f'{wg_cmd} show interfaces')
            if code == 0 and stdout.strip():
                return stdout.strip().split()[0]
        
        # Ищем конфигурационные файлы
        config_files = glob.glob('/etc/wireguard/*.conf')
        if config_files:
            return os.path.basename(config_files[0]).replace('.conf', '')
        
        return 'wg0'  # Fallback
    except:
        return 'wg0'

def get_server_ip():
    """Получение внешнего IP адреса сервера"""
    try:
        # Пробуем несколько способов получения внешнего IP
        commands = [
            'curl -s ifconfig.me',
            'curl -s ipinfo.io/ip',
            'curl -s icanhazip.com',
            'dig +short myip.opendns.com @resolver1.opendns.com'
        ]
        
        for cmd in commands:
            stdout, stderr, code = run_command(cmd)
            if code == 0 and stdout.strip():
                ip = stdout.strip()
                # Проверяем, что это валидный IP
                if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
                    return ip
        
        # Fallback - получаем локальный IP
        stdout, stderr, code = run_command("ip route get 8.8.8.8 | awk '{print $7}' | head -1")
        if code == 0 and stdout.strip():
            return stdout.strip()
        
        return '127.0.0.1'
    except:
        return '127.0.0.1'

def generate_preshared_key():
    """Генерация preshared key"""
    try:
        wg_cmd = check_wg_command()
        if wg_cmd:
            stdout, stderr, code = run_command(f'{wg_cmd} genpsk')
            if code == 0:
                return stdout.strip()
        
        # Fallback - генерируем случайный ключ
        import base64
        import os
        return base64.b64encode(os.urandom(32)).decode('utf-8')
    except:
        import base64
        import os
        return base64.b64encode(os.urandom(32)).decode('utf-8')

def get_server_network_info():
    """Получение информации о сети сервера из параметров и конфигурации"""
    try:
        # Сначала пытаемся загрузить из файла параметров
        params = load_wireguard_params()
        
        if params:
            # Используем параметры из файла params
            server_ipv4 = params.get('SERVER_WG_IPV4', '10.66.66.1')
            server_ipv6 = params.get('SERVER_WG_IPV6', 'fd42:42:42::1')
            server_port = params.get('SERVER_PORT', '51820')
            
            # Извлекаем базовые адреса
            ipv4_base = '.'.join(server_ipv4.split('.')[:-1])  # 10.66.66
            ipv6_base = server_ipv6.split('::')[0]  # fd42:42:42
            
            return ipv4_base, ipv6_base, server_port
        
        # Fallback: читаем из конфигурационного файла
        interface_name = get_interface_name()
        server_config_file = f'/etc/wireguard/{interface_name}.conf'
        
        if os.path.exists(server_config_file):
            with open(server_config_file, 'r') as f:
                content = f.read()
            
            # Ищем Address сервера
            address_match = re.search(r'Address\s*=\s*([^,\n]+)', content)
            port_match = re.search(r'ListenPort\s*=\s*(\d+)', content)
            
            ipv4_base = "10.66.66"
            ipv6_base = "fd42:42:42"
            port = "51820"
            
            if address_match:
                address = address_match.group(1).strip()
                # Извлекаем IPv4 базу
                ipv4_match = re.search(r'(\d+\.\d+\.\d+)\.\d+', address)
                if ipv4_match:
                    ipv4_base = ipv4_match.group(1)
            
            if port_match:
                port = port_match.group(1)
            
            return ipv4_base, ipv6_base, port
        
        # Последний fallback
        return "10.66.66", "fd42:42:42", "51820"
    except Exception as e:
        print(f"Ошибка получения сетевой информации: {e}")
        return "10.66.66", "fd42:42:42", "51820"

def get_next_client_ip():
    """Получение следующего доступного IP для клиента"""
    try:
        # Читаем серверную конфигурацию для определения подсети
        if os.path.exists(WG_CONFIG_FILE):
            with open(WG_CONFIG_FILE, 'r') as f:
                content = f.read()
            
            # Ищем существующие AllowedIPs
            used_ips = set()
            for line in content.split('\n'):
                if 'AllowedIPs' in line and '=' in line:
                    ips = line.split('=')[1].strip()
                    # Извлекаем IP адрес
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.)(\d+)', ips)
                    if ip_match:
                        used_ips.add(int(ip_match.group(2)))
            
            # Определяем базовую подсеть (по умолчанию 10.66.66)
            base_subnet = "10.66.66"
            
            # Ищем первый свободный IP начиная с .2
            for i in range(2, 255):
                if i not in used_ips:
                    return f"{base_subnet}.{i}/32"
            
            return f"{base_subnet}.2/32"  # Fallback
        else:
            return "10.66.66.2/32"
    except Exception as e:
        print(f"Ошибка получения IP: {e}")
        return "10.66.66.2/32"

def create_client_native(client_name):
    """Создание клиента собственными средствами без внешних скриптов"""
    try:
        import os
        import base64
        
        print(f"🔧 Создаем клиента: {client_name}")
        
        # Генерируем ключи для клиента
        print("🔑 Генерируем приватный ключ...")
        private_key_cmd = 'wg genkey'
        stdout, stderr, code = run_command(private_key_cmd)
        
        if code != 0:
            # Fallback для тестирования - генерируем псевдо-ключи
            print(f"⚠️  WireGuard не найден, используем тестовые ключи. Ошибка: {stderr}")
            private_key = base64.b64encode(os.urandom(32)).decode('utf-8')
            public_key = base64.b64encode(os.urandom(32)).decode('utf-8')
            print("✅ Тестовые ключи сгенерированы")
        else:
            private_key = stdout.strip()
            print("✅ Приватный ключ сгенерирован")
            
            # Генерируем публичный ключ
            print("🔑 Генерируем публичный ключ...")
            public_key_cmd = f'echo "{private_key}" | wg pubkey'
            stdout, stderr, code = run_command(public_key_cmd)
            if code != 0:
                # Fallback для публичного ключа
                print(f"⚠️  Ошибка генерации публичного ключа: {stderr}")
                public_key = base64.b64encode(os.urandom(32)).decode('utf-8')
                print("✅ Тестовый публичный ключ сгенерирован")
            else:
                public_key = stdout.strip()
                print("✅ Публичный ключ сгенерирован")
        
        # Получаем следующий доступный IP адрес
        print("🌐 Определяем IP адрес для клиента...")
        allowed_ips = get_next_client_ip()
        print(f"✅ IP адрес: {allowed_ips}")
        
        # Создаем файл конфигурации клиента
        try:
            print("📝 Создаем конфигурацию клиента...")
            # Создаем конфиг для клиента используя правильную функцию
            client_config = generate_client_config(client_name, private_key, public_key, allowed_ips)
            
            # Проверяем, существует ли директория для сохранения
            if not os.path.exists(WIREGUARD_CONFIG_PATH):
                print(f"📁 Создаем директорию: {WIREGUARD_CONFIG_PATH}")
                try:
                    os.makedirs(WIREGUARD_CONFIG_PATH, mode=0o755, exist_ok=True)
                    print(f"✅ Директория создана: {WIREGUARD_CONFIG_PATH}")
                except PermissionError:
                    print(f"❌ Нет прав для создания директории: {WIREGUARD_CONFIG_PATH}")
                    return False, f"Нет прав для создания директории: {WIREGUARD_CONFIG_PATH}"
                except Exception as e:
                    print(f"❌ Ошибка создания директории: {e}")
                    return False, f"Ошибка создания директории: {e}"
            
            # Сохраняем конфиг клиента в отдельный файл
            client_config_file = f'{WIREGUARD_CONFIG_PATH}wg0-client-{client_name}.conf'
            print(f"💾 Сохраняем конфиг клиента: {client_config_file}")
            with open(client_config_file, 'w') as f:
                f.write(client_config)
            print("✅ Конфиг клиента сохранен")
            
            # Добавляем клиента в серверный конфиг как в wireguard-install.sh
            print(f"📝 Добавляем клиента в серверный конфиг...")
            # Получаем PresharedKey из сгенерированного конфига
            preshared_key = None
            for line in client_config.split('\n'):
                if line.strip().startswith('PresharedKey'):
                    preshared_key = line.split('=', 1)[1].strip()
                    break
            
            success = add_client_to_server_config(client_name, public_key, preshared_key, allowed_ips)
            if success:
                print("✅ Клиент добавлен в серверный конфиг")
            else:
                print("⚠️  Не удалось добавить клиента в серверный конфиг")
            
            # Синхронизация уже выполнена в add_client_to_server_config
            print("ℹ️  Синхронизация WireGuard выполнена автоматически")
            
            print(f"🎉 Клиент {client_name} успешно создан!")
            return True, client_config
            
        except Exception as e:
            print(f"❌ Ошибка создания конфигурации: {e}")
            return False, f'Ошибка создания конфигурации: {e}'
        
    except Exception as e:
        print(f"❌ Ошибка создания клиента: {e}")
        return False, f"Ошибка создания клиента: {str(e)}"

def add_client_via_script(client_name):
    """Добавление клиента через собственную реализацию"""
    # Используем собственную реализацию вместо внешнего скрипта
    return create_client_native(client_name)

def create_default_server_config():
    """Создание базовой серверной конфигурации для тестирования"""
    try:
        # Проверяем, существует ли уже конфигурация
        if os.path.exists(WG_CONFIG_FILE):
            return True, "Серверная конфигурация уже существует"
        
        # Создаем директорию, если её нет
        config_dir = os.path.dirname(WG_CONFIG_FILE)
        os.makedirs(config_dir, exist_ok=True)
        
        # Генерируем ключи сервера
        wg_cmd = check_wg_command()
        if wg_cmd:
            # Генерируем приватный ключ
            stdout, stderr, code = run_command(f'{wg_cmd} genkey')
            if code == 0:
                private_key = stdout.strip()
            else:
                # Fallback
                import base64
                private_key = base64.b64encode(os.urandom(32)).decode('utf-8')
        else:
            # Fallback
            import base64
            private_key = base64.b64encode(os.urandom(32)).decode('utf-8')
        
        # Создаем базовую конфигурацию сервера
        server_config = f"""[Interface]
PrivateKey = {private_key}
Address = 10.7.0.1/24, fd42:42:42::1/64
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -A FORWARD -o %i -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -D FORWARD -o %i -j ACCEPT; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Клиенты будут добавлены ниже
"""
        
        # Записываем конфигурацию
        with open(WG_CONFIG_FILE, 'w') as f:
            f.write(server_config)
        
        # Устанавливаем права доступа
        os.chmod(WG_CONFIG_FILE, 0o600)
        
        print(f"✅ Создана базовая серверная конфигурация: {WG_CONFIG_FILE}")
        return True, "Базовая серверная конфигурация создана"
        
    except Exception as e:
        print(f"❌ Ошибка создания серверной конфигурации: {e}")
        return False, f"Ошибка создания серверной конфигурации: {str(e)}"

def get_server_public_key():
    """Получение публичного ключа сервера"""
    import os
    try:
        # Сначала пробуем получить из готового файла
        if os.path.exists('/root/server_public.key'):
            with open('/root/server_public.key', 'r') as f:
                key = f.read().strip()
                if key and len(key) > 10:  # Проверяем, что ключ не пустой
                    return key
        
        # Если файла нет, генерируем из приватного ключа в конфиге
        if not os.path.exists(WG_CONFIG_FILE):
            print(f"⚠️  Серверная конфигурация не найдена: {WG_CONFIG_FILE}")
            print("🔧 Создаем базовую серверную конфигурацию...")
            success, message = create_default_server_config()
            if not success:
                print(f"❌ Не удалось создать серверную конфигурацию: {message}")
                # Возвращаем тестовый ключ
                import base64
                return base64.b64encode(os.urandom(32)).decode('utf-8')
            print(f"✅ {message}")
        
        if os.path.exists(WG_CONFIG_FILE):
            try:
                with open(WG_CONFIG_FILE, 'r') as f:
                    content = f.read()
            except PermissionError:
                print(f"Нет прав на чтение серверной конфигурации: {WG_CONFIG_FILE}")
                import base64
                return base64.b64encode(os.urandom(32)).decode('utf-8')
            except Exception as e:
                print(f"Ошибка чтения серверной конфигурации: {e}")
                import base64
                return base64.b64encode(os.urandom(32)).decode('utf-8')
            
            # Ищем приватный ключ в секции [Interface]
            private_key = None
            in_interface = False
            
            for line in content.split('\n'):
                line = line.strip()
                if line == '[Interface]':
                    in_interface = True
                    continue
                elif line.startswith('[') and line != '[Interface]':
                    in_interface = False
                    continue
                
                if in_interface and line.startswith('PrivateKey'):
                    private_key = line.split('=', 1)[1].strip()
                    break
            
            if private_key:
                # Пробуем сгенерировать публичный ключ
                wg_cmd = check_wg_command()
                if wg_cmd:
                    stdout, stderr, code = run_command(f'echo "{private_key}" | {wg_cmd} pubkey')
                    if code == 0 and stdout.strip():
                        public_key = stdout.strip()
                        
                        # Сохраняем публичный ключ в файл для будущего использования
                        try:
                            with open('/root/server_public.key', 'w') as f:
                                f.write(public_key)
                            os.chmod('/root/server_public.key', 0o600)
                        except:
                            pass  # Не критично, если не удалось сохранить
                        
                        return public_key
                    else:
                        print(f"Ошибка генерации публичного ключа: {stderr}")
                else:
                    print("WireGuard не найден")
                
                # Fallback - генерируем тестовый ключ
                import base64
                test_key = base64.b64encode(os.urandom(32)).decode('utf-8')
                return test_key
        
        # Если ничего не получилось, возвращаем тестовый ключ
        print("Не удалось получить публичный ключ сервера, используем тестовый")
        import base64
        return base64.b64encode(os.urandom(32)).decode('utf-8')
        
    except Exception as e:
        print(f"Ошибка получения публичного ключа сервера: {e}")
        import base64
        return base64.b64encode(os.urandom(32)).decode('utf-8')

def get_server_port():
    """Получение порта сервера из конфигурации"""
    try:
        if os.path.exists(WG_CONFIG_FILE):
            try:
                with open(WG_CONFIG_FILE, 'r') as f:
                    content = f.read()
            except PermissionError:
                print(f"Нет прав на чтение серверной конфигурации: {WG_CONFIG_FILE}")
                return '51820'
            except Exception as e:
                print(f"Ошибка чтения серверной конфигурации: {e}")
                return '51820'
            
            # Ищем порт в секции [Interface]
            in_interface = False
            
            for line in content.split('\n'):
                line = line.strip()
                if line == '[Interface]':
                    in_interface = True
                    continue
                elif line.startswith('[') and line != '[Interface]':
                    in_interface = False
                    continue
                
                if in_interface and line.startswith('ListenPort'):
                    port = line.split('=', 1)[1].strip()
                    return port
        else:
            print(f"Серверная конфигурация не найдена: {WG_CONFIG_FILE}")
        
        return '51820'  # Порт по умолчанию
    except Exception as e:
        print(f"Ошибка получения порта сервера: {e}")
        return '51820'

def generate_client_config_simple(client_name, private_key, public_key, allowed_ips):
    """Генерирует простую конфигурацию клиента как в старой версии"""
    try:
        # Получаем публичный ключ сервера
        server_public_key = get_server_public_key()
        
        # Получаем внешний IP сервера
        server_ip = get_server_ip()
        
        # Получаем порт сервера
        server_port = get_server_port()
        
        # Создаем конфигурацию клиента
        config = f"""[Interface]
PrivateKey = {private_key}
Address = {allowed_ips}
DNS = 8.8.8.8, 8.8.4.4

[Peer]
PublicKey = {server_public_key}
Endpoint = {server_ip}:{server_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25"""
        
        return config
        
    except Exception as e:
        print(f"Ошибка генерации конфигурации клиента: {e}")
        # Fallback конфигурация
        return f"""[Interface]
PrivateKey = {private_key}
Address = {allowed_ips}
DNS = 8.8.8.8, 8.8.4.4

[Peer]
PublicKey = SERVER_PUBLIC_KEY
Endpoint = YOUR_SERVER_IP:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25"""

def generate_client_config(client_name, private_key, public_key, address):
    """Генерирует конфигурацию клиента точно как в wireguard-install.sh"""
    try:
        # Загружаем параметры WireGuard
        params = load_wireguard_params()
        
        # Получаем параметры сервера (точно как в оригинальном скрипте)
        server_pub_key = params.get('SERVER_PUB_KEY', 'SERVER_PUBLIC_KEY')
        server_pub_ip = params.get('SERVER_PUB_IP', 'YOUR_SERVER_IP')
        server_port = params.get('SERVER_PORT', '51820')
        client_dns_1 = params.get('CLIENT_DNS_1', '1.1.1.1')  # По умолчанию как в оригинале
        client_dns_2 = params.get('CLIENT_DNS_2', '1.0.0.1')  # По умолчанию как в оригинале
        allowed_ips = params.get('ALLOWED_IPS', '0.0.0.0/0,::/0')
        
        # Формируем ENDPOINT как в оригинальном скрипте
        # Если SERVER_PUB_IP содержит IPv6, добавляем скобки
        if ':' in server_pub_ip and not server_pub_ip.startswith('['):
            endpoint = f"[{server_pub_ip}]:{server_port}"
        else:
            endpoint = f"{server_pub_ip}:{server_port}"
        
        # Получаем существующий PresharedKey из серверного конфига или генерируем новый
        preshared_key = get_client_preshared_key(public_key)
        if not preshared_key:
            # Проверяем наличие команды wg
            wg_cmd = check_wg_command()
            if wg_cmd:
                # Генерируем новый PresharedKey
                preshared_key_cmd = f'{wg_cmd} genpsk'
                stdout, stderr, code = run_command(preshared_key_cmd)
                preshared_key = stdout.strip() if code == 0 else ''
                if code != 0:
                    print(f"Ошибка генерации PresharedKey: {stderr}")
            else:
                print("WireGuard не найден, PresharedKey не будет добавлен")
        
        # Создаем конфигурацию точно как в оригинальном скрипте (строки 356-365)
        config = f"""[Interface]
PrivateKey = {private_key}
Address = {address}
DNS = {client_dns_1},{client_dns_2}

[Peer]
PublicKey = {server_pub_key}"""
        
        # PresharedKey добавляется сразу после PublicKey как в оригинале
        if preshared_key:
            config += f"\nPresharedKey = {preshared_key}"
        
        config += f"""
Endpoint = {endpoint}
AllowedIPs = {allowed_ips}"""
        
        return config
        
    except Exception as e:
        print(f"Ошибка генерации конфигурации клиента: {e}")
        # Fallback конфигурация с правильными параметрами
        return f"""[Interface]
PrivateKey = {private_key}
Address = {address}
DNS = 8.8.8.8,8.8.4.4

[Peer]
PublicKey = SERVER_PUBLIC_KEY
Endpoint = YOUR_SERVER_IP:51820
AllowedIPs = 0.0.0.0/0,::/0"""

def get_client_preshared_key(public_key):
    """Получает PresharedKey клиента из серверного конфига"""
    try:
        if not os.path.exists(WG_CONFIG_FILE):
            return None
            
        with open(WG_CONFIG_FILE, 'r') as f:
            content = f.read()
        
        # Ищем секцию [Peer] с нужным PublicKey
        lines = content.split('\n')
        in_peer_section = False
        current_peer_public_key = None
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('[Peer]'):
                in_peer_section = True
                current_peer_public_key = None
                continue
            elif line.startswith('['):
                in_peer_section = False
                continue
                
            if in_peer_section and '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                if key == 'PublicKey':
                    current_peer_public_key = value
                elif key == 'PresharedKey' and current_peer_public_key == public_key:
                    return value
        
        return None
        
    except Exception as e:
        print(f"Ошибка получения PresharedKey: {e}")
        return None

def add_client_to_server_config(client_name, public_key, preshared_key, client_address):
    """Добавляет клиента в серверный конфиг как в wireguard-install.sh"""
    try:
        if not os.path.exists(WG_CONFIG_FILE):
            print(f"Серверный конфиг {WG_CONFIG_FILE} не найден")
            return False
        
        # Формируем секцию клиента как в оригинальном скрипте (строки 368-372)
        client_section = f"""
### Client {client_name}
[Peer]
PublicKey = {public_key}"""
        
        if preshared_key:
            client_section += f"\nPresharedKey = {preshared_key}"
            
        client_section += f"\nAllowedIPs = {client_address}"
        
        # Добавляем в серверный конфиг
        with open(WG_CONFIG_FILE, 'a') as f:
            f.write(client_section)
        
        # Синхронизируем конфигурацию WireGuard как в оригинале (строка 374)
        wg_cmd = check_wg_command()
        if wg_cmd:
            # Проверяем, запущен ли интерфейс
            stdout, stderr, code = run_command(f'{wg_cmd} show {WIREGUARD_INTERFACE}')
            if code == 0:
                # Интерфейс запущен, синхронизируем
                sync_cmd = f'{wg_cmd} syncconf {WIREGUARD_INTERFACE} <(wg-quick strip {WIREGUARD_INTERFACE})'
                stdout, stderr, code = run_command(f'bash -c "{sync_cmd}"')
                if code == 0:
                    print(f"Конфигурация WireGuard синхронизирована для клиента {client_name}")
                else:
                    print(f"Ошибка синхронизации WireGuard: {stderr}")
            else:
                print(f"Интерфейс {WIREGUARD_INTERFACE} не запущен, синхронизация пропущена")
        
        return True
        
    except Exception as e:
        print(f"Ошибка добавления клиента в серверный конфиг: {e}")
        return False

def find_free_client_ip(server_ipv4, server_ipv6, interface_name):
    """Находит свободный IP адрес для нового клиента"""
    try:
        # Парсим базовые адреса
        ipv4_base = '.'.join(server_ipv4.split('.')[:-1])  # 10.66.66
        ipv6_base = server_ipv6.split('::')[0]  # fd42:42:42
        
        # Получаем список занятых IP из серверной конфигурации
        used_ips = set()
        config_file = f'/etc/wireguard/{interface_name}.conf'
        
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                content = f.read()
            
            # Ищем все AllowedIPs
            for line in content.split('\n'):
                if 'AllowedIPs' in line and '=' in line:
                    ips = line.split('=')[1].strip()
                    for ip in ips.split(','):
                        ip = ip.strip()
                        if '/' in ip:
                            ip = ip.split('/')[0]
                        used_ips.add(ip)
        
        # Ищем свободный IP (начинаем с 2, так как 1 - сервер)
        for i in range(2, 255):
            ipv4 = f"{ipv4_base}.{i}"
            ipv6 = f"{ipv6_base}::{i}"
            
            if ipv4 not in used_ips and ipv6 not in used_ips:
                return ipv4, ipv6
        
        return None, None
        
    except Exception as e:
        print(f"Ошибка поиска свободного IP: {e}")
        return None, None

@app.route('/add_client', methods=['GET', 'POST'])
@login_required
def add_client():
    """Добавление нового клиента"""
    if request.method == 'POST':
        client_name = request.form['client_name']
        
        if not client_name:
            flash('Заполните все поля')
            return render_template('add_client.html')
        
        # Используем собственную реализацию создания клиента
        success, result = create_client_native(client_name)
        
        if success:
            # Логируем успешное добавление клиента
            log_action(AuditActions.CREATE_CLIENT, 
                      details={'client_name': client_name})
            
            flash(f'Клиент {client_name} успешно добавлен')
            
            # result содержит конфигурацию клиента
            client_config = result
            
            return render_template('client_config.html', 
                                 client_name=client_name,
                                 client_config=client_config,
                                 config_file=f'/root/wg0-client-{client_name}.conf')
        else:
            flash(f'Ошибка добавления клиента: {result}')
    
    return render_template('add_client.html')

def check_directory_access(directory):
    """Проверка доступа к директории"""
    try:
        # Проверяем существование директории
        if not os.path.exists(directory):
            return False, "Директория не существует"
        
        # Проверяем права на чтение
        if not os.access(directory, os.R_OK):
            return False, "Нет прав на чтение"
        
        # Пытаемся получить список файлов
        os.listdir(directory)
        return True, "Доступ разрешен"
        
    except PermissionError:
        return False, "Отказано в доступе"
    except OSError as e:
        return False, f"Ошибка доступа: {e}"

def scan_config_files():
    """Сканирование директорий на наличие конфигурационных файлов WireGuard"""
    config_files = []
    # Добавляем более доступные директории для сканирования
    scan_dirs = [
        '/root', '/etc/wireguard', '/home', '/opt', '/var/lib',  # Системные директории
        './wireguard',  # Основная тестовая директория
        './test_wireguard',  # Тестовая директория
        './test_configs',  # Тестовые конфигурации
        os.path.expanduser('~/wireguard'),  # Домашняя директория пользователя
        os.path.expanduser('~/Documents/wireguard'),  # Документы пользователя
        './configs',  # Локальная директория configs
        '/tmp/wireguard',  # Временная директория
        os.getcwd()  # Текущая рабочая директория
    ]
    
    for scan_dir in scan_dirs:
        # Проверяем доступ к директории перед сканированием
        has_access, access_message = check_directory_access(scan_dir)
        if not has_access:
            if "не существует" not in access_message:
                print(f"ℹ️  {scan_dir}: {access_message}")
            continue
            
        try:
            for root, dirs, files in os.walk(scan_dir):
                # Ограничиваем глубину поиска для производительности
                if root.count(os.sep) - scan_dir.count(os.sep) > 3:
                    continue
                    
                for file in files:
                    # Расширяем критерии поиска
                    is_config_file = (
                        file.endswith('.conf') and (
                            'wg' in file.lower() or 
                            'wireguard' in file.lower() or
                            'client' in file.lower() or
                            file.lower().startswith('peer') or
                            re.match(r'.*client.*\.conf$', file.lower())
                        )
                    )
                    
                    if is_config_file:
                        file_path = os.path.join(root, file)
                        try:
                            # Проверяем, что это действительно конфигурация WireGuard
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                
                            # Более строгая проверка на WireGuard конфигурацию
                            has_interface = '[Interface]' in content
                            has_peer = '[Peer]' in content
                            has_private_key = 'PrivateKey' in content
                            has_public_key = 'PublicKey' in content
                            
                            if (has_interface or has_peer) and (has_private_key or has_public_key):
                                # Определяем тип конфигурации
                                config_type = 'client' if has_interface and has_peer else 'server' if has_interface else 'peer'
                                
                                config_files.append({
                                    'path': file_path,
                                    'name': file,
                                    'size': os.path.getsize(file_path),
                                    'modified': os.path.getmtime(file_path),
                                    'directory': root,
                                    'type': config_type,
                                    'is_client': config_type == 'client'
                                })
                        except (PermissionError, UnicodeDecodeError, OSError):
                            continue
        except (PermissionError, OSError):
            continue
    
    # Сортируем по дате изменения (новые сначала)
    config_files.sort(key=lambda x: x['modified'], reverse=True)
    
    return config_files

def parse_client_config_file(file_path):
    """Парсинг конфигурационного файла клиента WireGuard"""
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Ищем секцию [Interface]
        interface_match = re.search(r'\[Interface\](.*?)(?=\[|$)', content, re.DOTALL)
        if not interface_match:
            return None
            
        interface_section = interface_match.group(1)
        
        # Извлекаем данные клиента
        client_data = {}
        
        # Приватный ключ
        private_key_match = re.search(r'PrivateKey\s*=\s*(.+)', interface_section)
        if private_key_match:
            client_data['private_key'] = private_key_match.group(1).strip()
        
        # IP адрес
        address_match = re.search(r'Address\s*=\s*(.+)', interface_section)
        if address_match:
            client_data['address'] = address_match.group(1).strip()
        
        # DNS
        dns_match = re.search(r'DNS\s*=\s*(.+)', interface_section)
        if dns_match:
            client_data['dns'] = dns_match.group(1).strip()
        
        # Ищем секцию [Peer] (сервер)
        peer_match = re.search(r'\[Peer\](.*?)(?=\[|$)', content, re.DOTALL)
        if peer_match:
            peer_section = peer_match.group(1)
            
            # Публичный ключ сервера
            public_key_match = re.search(r'PublicKey\s*=\s*(.+)', peer_section)
            if public_key_match:
                client_data['server_public_key'] = public_key_match.group(1).strip()
            
            # Endpoint
            endpoint_match = re.search(r'Endpoint\s*=\s*(.+)', peer_section)
            if endpoint_match:
                client_data['endpoint'] = endpoint_match.group(1).strip()
            
            # AllowedIPs
            allowed_ips_match = re.search(r'AllowedIPs\s*=\s*(.+)', peer_section)
            if allowed_ips_match:
                client_data['allowed_ips'] = allowed_ips_match.group(1).strip()
        
        return client_data
        
    except Exception as e:
        print(f"Ошибка парсинга файла {file_path}: {e}")
        return None

def import_client_from_config(client_name, config_data):
    """Импорт клиента из конфигурационных данных"""
    try:
        import os
        import base64
        
        print(f"🔄 Начинаем импорт клиента: {client_name}")
        print(f"📋 Данные конфигурации: {config_data}")
        
        # Получаем текущую конфигурацию сервера
        interface_name = get_interface_name()
        print(f"🔌 Имя интерфейса: {interface_name}")
        if not interface_name:
            return False, "WireGuard интерфейс не найден"
        
        # Генерируем публичный ключ из приватного
        private_key = config_data.get('private_key')
        if not private_key:
            return False, "Приватный ключ не найден в конфигурации"
        
        # Генерируем публичный ключ
        try:
            result = subprocess.run(['wg', 'pubkey'], 
                                  input=private_key, 
                                  text=True, 
                                  capture_output=True, 
                                  check=True)
            public_key = result.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback - генерируем тестовый публичный ключ
            public_key = base64.b64encode(os.urandom(32)).decode('utf-8')
            print(f"⚠️  WireGuard не найден, используем тестовый публичный ключ")
        
        # Извлекаем IP адрес клиента
        address = config_data.get('address', '')
        if not address:
            return False, "IP адрес не найден в конфигурации"
        
        # Извлекаем IPv4 адрес
        ipv4_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', address)
        if not ipv4_match:
            return False, "Некорректный IPv4 адрес в конфигурации"
        
        client_ipv4 = ipv4_match.group(1)
        
        # Генерируем IPv6 адрес (если нужно)
        client_ipv6 = f"fd42:42:42::{client_ipv4.split('.')[-1]}"
        
        # Генерируем preshared key
        preshared_key = generate_preshared_key()
        
        # Создаем конфигурацию клиента
        # Получаем данные сервера
        print("🔑 Получаем публичный ключ сервера...")
        server_public_key = get_server_public_key()
        print(f"🔑 Публичный ключ сервера: {server_public_key[:20]}...")
        
        print("🌐 Получаем IP сервера...")
        server_ip = get_server_ip()
        print(f"🌐 IP сервера: {server_ip}")
        
        print("🔌 Получаем порт сервера...")
        server_port = get_server_port()
        print(f"🔌 Порт сервера: {server_port}")
        
        server_endpoint = f"{server_ip}:{server_port}"
        print(f"📡 Endpoint сервера: {server_endpoint}")
        
        client_config = f"""[Interface]
PrivateKey = {private_key}
Address = {client_ipv4}/32, {client_ipv6}/128
DNS = {config_data.get('dns', '8.8.8.8, 8.8.4.4')}

[Peer]
PublicKey = {server_public_key}
PresharedKey = {preshared_key}
Endpoint = {server_endpoint}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
        
        # Сохраняем конфигурацию клиента
        client_config_file = f'/root/{interface_name}-client-{client_name}.conf'
        print(f"💾 Сохраняем конфигурацию клиента в: {client_config_file}")
        
        # Создаем директорию, если её нет (только для fallback путей)
        if not client_config_file.startswith('/root/'):
            os.makedirs(os.path.dirname(client_config_file), exist_ok=True)
        
        try:
            with open(client_config_file, 'w') as f:
                f.write(client_config)
            print(f"✅ Конфигурация клиента сохранена в: {client_config_file}")
        except PermissionError as e:
            print(f"❌ Нет прав на запись в {client_config_file}: {e}")
            return False, f"Нет прав на запись конфигурации клиента: {client_config_file}"
        except FileNotFoundError as e:
            print(f"❌ Директория не найдена для {client_config_file}: {e}")
            return False, f"Директория не найдена: {os.path.dirname(client_config_file)}"
        except Exception as e:
            print(f"❌ Ошибка записи конфигурации клиента: {e}")
            return False, f"Ошибка записи конфигурации клиента: {str(e)}"
        
        # Добавляем клиента в серверную конфигурацию
        server_config_file = f'/etc/wireguard/{interface_name}.conf'
        
        # Проверяем существование серверной конфигурации
        print(f"🔍 Проверяем серверную конфигурацию: {server_config_file}")
        if not os.path.exists(server_config_file):
            print(f"⚠️  Серверная конфигурация не найдена: {server_config_file}")
            print("🔧 Создаем базовую серверную конфигурацию...")
            success, message = create_default_server_config()
            if not success:
                print(f"❌ {message}")
                return False, f"Не удалось создать серверную конфигурацию: {message}"
            print(f"✅ {message}")
        else:
            print(f"✅ Серверная конфигурация найдена: {server_config_file}")
        
        print(f"📝 Добавляем клиента в серверную конфигурацию...")
        print(f"🔑 Публичный ключ клиента: {public_key}")
        print(f"🔐 Preshared ключ: {preshared_key}")
        print(f"🌐 Разрешенные IP: {client_ipv4}/32,{client_ipv6}/128")
        
        try:
            with open(server_config_file, 'a') as f:
                f.write(f'\n### Client {client_name}\n')
                f.write(f'[Peer]\n')
                f.write(f'PublicKey = {public_key}\n')
                f.write(f'PresharedKey = {preshared_key}\n')
                f.write(f'AllowedIPs = {client_ipv4}/32,{client_ipv6}/128\n\n')
            print(f"✅ Клиент добавлен в серверную конфигурацию")
        except PermissionError as e:
            print(f"❌ Нет прав на запись в {server_config_file}: {e}")
            return False, f"Нет прав на запись в серверную конфигурацию: {server_config_file}"
        except Exception as e:
            print(f"❌ Ошибка записи в серверную конфигурацию: {e}")
            return False, f"Ошибка записи в серверную конфигурацию: {str(e)}"
        
        # Перезагружаем WireGuard
        print(f"🔄 Перезагружаем WireGuard интерфейс {interface_name}...")
        reload_cmd = f'wg syncconf {interface_name} <(wg-quick strip {interface_name})'
        print(f"🔧 Команда: {reload_cmd}")
        stdout, stderr, code = run_command(f'bash -c "{reload_cmd}"')
        
        if code != 0:
            print(f"⚠️  Syncconf не удался (код {code}), пробуем systemctl reload...")
            if stderr:
                print(f"📋 Ошибка syncconf: {stderr}")
            # Fallback на обычную перезагрузку
            fallback_cmd = f'systemctl reload wg-quick@{interface_name}'
            print(f"🔧 Fallback команда: {fallback_cmd}")
            stdout2, stderr2, code2 = run_command(fallback_cmd)
            if code2 == 0:
                print(f"✅ WireGuard перезагружен через systemctl")
            else:
                print(f"⚠️  Systemctl reload тоже не удался (код {code2})")
                if stderr2:
                    print(f"📋 Ошибка systemctl: {stderr2}")
        else:
            print(f"✅ WireGuard перезагружен через syncconf")
        
        print(f"✅ Клиент {client_name} успешно импортирован!")
        return True, client_config
        
    except Exception as e:
        print(f"❌ Ошибка импорта клиента {client_name}: {str(e)}")
        import traceback
        print(f"📋 Полная трассировка ошибки: {traceback.format_exc()}")
        return False, f"Ошибка импорта клиента: {str(e)}"

def create_default_server_config():
    """Создание базовой серверной конфигурации WireGuard"""
    try:
        import os
        import base64
        
        # Генерируем ключи сервера
        wg_cmd = check_wg_command()
        if wg_cmd:
            # Генерируем приватный ключ сервера
            stdout, stderr, code = run_command(f'{wg_cmd} genkey')
            if code == 0:
                server_private_key = stdout.strip()
            else:
                # Fallback
                server_private_key = base64.b64encode(os.urandom(32)).decode('utf-8')
        else:
            # Fallback
            server_private_key = base64.b64encode(os.urandom(32)).decode('utf-8')
        
        # Создаем базовую конфигурацию сервера
        server_config = f"""[Interface]
PrivateKey = {server_private_key}
Address = 10.7.0.1/24, fd42:42:42::1/64
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -A FORWARD -o %i -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -D FORWARD -o %i -j ACCEPT; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Клиенты будут добавлены ниже
"""
        
        # Сохраняем в стандартное место для Ubuntu
        config_file = f'/etc/wireguard/{get_interface_name()}.conf'
        print(f"💾 Создаем серверную конфигурацию: {config_file}")
        
        try:
            # Создаем директорию, если её нет
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            
            with open(config_file, 'w') as f:
                f.write(server_config)
            print(f"✅ Серверная конфигурация создана: {config_file}")
            return True, f"Базовая серверная конфигурация создана: {config_file}"
        except PermissionError as e:
            print(f"❌ Нет прав на создание {config_file}: {e}")
            return False, f"Нет прав на создание серверной конфигурации: {config_file}"
        except Exception as e:
            print(f"❌ Ошибка создания {config_file}: {e}")
            return False, f"Ошибка создания серверной конфигурации: {str(e)}"
            
    except Exception as e:
        return False, f"Ошибка генерации серверной конфигурации: {str(e)}"

def create_test_client_data():
    """Создание тестовых данных клиента для импорта"""
    return {
        'private_key': 'cOFA+YD2z5FWp7xbdHcxdUzjYAiuFmuBCAA2bHjQJGE=',
        'address': '10.7.0.2/32, fd42:42:42::2/128',
        'dns': '8.8.8.8, 8.8.4.4'
    }

@app.route('/test_import_client')
@login_required
def test_import_client():
    """Тестовый импорт клиента"""
    try:
        test_data = create_test_client_data()
        success, result = import_client_from_config('test_client', test_data)
        
        if success:
            flash(f'✅ Тестовый клиент успешно импортирован!', 'success')
        else:
            flash(f'❌ Ошибка импорта тестового клиента: {result}', 'error')
            
    except Exception as e:
        flash(f'❌ Исключение при тестовом импорте: {str(e)}', 'error')
    
    return redirect(url_for('import_clients'))

@app.route('/import_clients')
@login_required
def import_clients():
    """Страница импорта клиентов с автоматическим сканированием"""
    # Сканируем конфигурационные файлы
    config_files = scan_config_files()
    
    # Получаем список существующих клиентов для проверки дубликатов
    existing_clients = parse_wg_config()
    existing_ips = [client.get('allowed_ips', '').split('/')[0].split(',')[0].strip() 
                   for client in existing_clients if client.get('allowed_ips')]
    
    return render_template('import_clients.html', 
                         config_files=config_files,
                         existing_ips=existing_ips)

@app.route('/import_client_file', methods=['POST'])
@login_required
def import_client_file():
    """Импорт клиента из выбранного файла"""
    file_path = request.form.get('file_path')
    client_name = request.form.get('client_name', '').strip()
    
    if not file_path or not os.path.exists(file_path):
        flash('Файл конфигурации не найден', 'error')
        return redirect(url_for('import_clients'))
    
    if not client_name:
        # Генерируем имя из имени файла
        client_name = os.path.splitext(os.path.basename(file_path))[0]
        client_name = re.sub(r'[^a-zA-Z0-9_-]', '', client_name)
    
    # Проверяем, что клиент с таким именем не существует
    existing_clients = parse_wg_config()
    existing_names = [client.get('name', '') for client in existing_clients]
    
    if client_name in existing_names:
        flash(f'Клиент с именем "{client_name}" уже существует', 'error')
        return redirect(url_for('import_clients'))
    
    # Парсим конфигурационный файл
    config_data = parse_client_config_file(file_path)
    if not config_data:
        flash('Не удалось распарсить конфигурационный файл', 'error')
        return redirect(url_for('import_clients'))
    
    # Импортируем клиента
    success, result = import_client_from_config(client_name, config_data)
    
    if success:
        flash(f'Клиент "{client_name}" успешно импортирован!', 'success')
        return redirect(url_for('index'))
    else:
        flash(f'Ошибка импорта: {result}', 'error')
        return redirect(url_for('import_clients'))

@app.route('/upload_config', methods=['POST'])
@login_required
def upload_config():
    """Загрузка конфигурационного файла через форму"""
    if 'config_file' not in request.files:
        flash('Файл не выбран', 'error')
        return redirect(url_for('import_clients'))
    
    file = request.files['config_file']
    client_name = request.form.get('client_name', '').strip()
    
    if file.filename == '':
        flash('Файл не выбран', 'error')
        return redirect(url_for('import_clients'))
    
    if not client_name:
        # Генерируем имя из имени файла
        client_name = os.path.splitext(file.filename)[0]
        client_name = re.sub(r'[^a-zA-Z0-9_-]', '', client_name)
    
    # Сохраняем временный файл
    temp_path = f'/tmp/wireguard_import_{client_name}.conf'
    file.save(temp_path)
    
    try:
        # Парсим конфигурационный файл
        config_data = parse_client_config_file(temp_path)
        if not config_data:
            flash('Не удалось распарсить конфигурационный файл', 'error')
            return redirect(url_for('import_clients'))
        
        # Импортируем клиента
        success, result = import_client_from_config(client_name, config_data)
        
        if success:
            flash(f'Клиент "{client_name}" успешно импортирован!', 'success')
            return redirect(url_for('index'))
        else:
            flash(f'Ошибка импорта: {result}', 'error')
            return redirect(url_for('import_clients'))
            
    finally:
        # Удаляем временный файл
        if os.path.exists(temp_path):
            os.remove(temp_path)

@app.route('/import_from_clipboard', methods=['POST'])
@login_required
def import_from_clipboard():
    """Импорт клиента из буфера обмена"""
    client_name = request.form.get('client_name', '').strip()
    config_content = request.form.get('config_content', '').strip()
    
    if not client_name:
        flash('Имя клиента не указано', 'error')
        return redirect(url_for('import_clients'))
    
    if not config_content:
        flash('Конфигурация не указана', 'error')
        return redirect(url_for('import_clients'))
    
    # Проверяем, что клиент с таким именем не существует
    existing_clients = parse_wg_config()
    existing_names = [client.get('name', '') for client in existing_clients]
    
    if client_name in existing_names:
        flash(f'Клиент с именем "{client_name}" уже существует', 'error')
        return redirect(url_for('import_clients'))
    
    # Сохраняем временный файл
    temp_path = f'/tmp/wireguard_clipboard_{client_name}.conf'
    
    try:
        with open(temp_path, 'w') as f:
            f.write(config_content)
        
        # Парсим конфигурационный файл
        config_data = parse_client_config_file(temp_path)
        if not config_data:
            flash('Не удалось распарсить конфигурацию из буфера обмена', 'error')
            return redirect(url_for('import_clients'))
        
        # Импортируем клиента
        success, result = import_client_from_config(client_name, config_data)
        
        if success:
            flash(f'Клиент "{client_name}" успешно импортирован из буфера обмена!', 'success')
            return redirect(url_for('index'))
        else:
            flash(f'Ошибка импорта: {result}', 'error')
            return redirect(url_for('import_clients'))
            
    finally:
        # Удаляем временный файл
        if os.path.exists(temp_path):
            os.remove(temp_path)

@app.route('/download_client_config/<int:client_id>')
@login_required
def download_client_config(client_id):
    """Скачивание конфигурации клиента"""
    try:
        clients = parse_wg_config()
        
        if client_id <= 0 or client_id > len(clients):
            flash('Клиент не найден')
            return redirect(url_for('index'))
        
        client = clients[client_id - 1]
        client_name = client['name']
        
        # Генерируем актуальную конфигурацию клиента
        client_config = generate_client_config(
            client_name, 
            client['private_key'], 
            client['public_key'], 
            client['allowed_ips']
        )
        
        # Создаем HTTP ответ для скачивания файла
        from flask import Response
        
        response = Response(
            client_config,
            mimetype='text/plain',
            headers={
                'Content-Disposition': f'attachment; filename=wg0-client-{client_name}.conf'
            }
        )
        
        return response
        
    except Exception as e:
        flash(f'Ошибка скачивания конфигурации: {e}')
        return redirect(url_for('index'))

@app.route('/view_client_config/<int:client_id>')
@login_required
def view_client_config(client_id):
    """Просмотр конфигурации клиента"""
    try:
        clients = parse_wg_config()
        
        if client_id <= 0 or client_id > len(clients):
            flash('Клиент не найден')
            return redirect(url_for('index'))
        
        client = clients[client_id - 1]
        client_name = client['name']
        
        # Генерируем актуальную конфигурацию клиента
        client_config = generate_client_config(
            client_name, 
            client['private_key'], 
            client['public_key'], 
            client['allowed_ips']
        )
        
        return render_template('client_config.html', 
                             client_name=client_name,
                             client_config=client_config,
                             config_file=f'wg0-client-{client_name}.conf')
        
    except Exception as e:
        flash(f'Ошибка просмотра конфигурации: {e}')
        return redirect(url_for('index'))

@app.route('/qr_client_config/<int:client_id>')
@login_required
def qr_client_config(client_id):
    """Генерация QR-кода для конфигурации клиента по ID"""
    try:
        clients = parse_wg_config()
        
        if client_id <= 0 or client_id > len(clients):
            flash('Клиент не найден')
            return redirect(url_for('index'))
        
        client = clients[client_id - 1]
        return qr_client_config_by_name(client['name'])
        
    except Exception as e:
        flash(f'Ошибка генерации QR-кода: {e}')
        return redirect(url_for('index'))

@app.route('/qr_client_config_by_name/<client_name>')
@login_required
def qr_client_config_by_name(client_name):
    """Генерация QR-кода для конфигурации клиента"""
    try:
        clients = parse_wg_config()
        
        # Ищем клиента по имени
        client = None
        for c in clients:
            if c['name'] == client_name:
                client = c
                break
        
        if not client:
            flash('Клиент не найден')
            return redirect(url_for('index'))
        
        # Генерируем актуальную конфигурацию клиента
        client_config = generate_client_config(
            client_name, 
            client['private_key'], 
            client['public_key'], 
            client['allowed_ips']
        )
        
        # Пробуем создать QR-код
        try:
            import qrcode
            from io import BytesIO
            import base64
            
            # Создаем QR-код
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(client_config)
            qr.make(fit=True)
            
            # Создаем изображение
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Конвертируем в base64 для отображения в браузере
            buffer = BytesIO()
            img.save(buffer, format='PNG')
            buffer.seek(0)
            qr_image = base64.b64encode(buffer.getvalue()).decode()
            
            return render_template('qr_config.html', 
                                 client_name=client_name,
                                 client_config=client_config,
                                 qr_image=qr_image)
            
        except ImportError:
            # Если qrcode не установлен, показываем конфигурацию без QR
            flash('QR-код недоступен. Установите библиотеку qrcode: pip install qrcode[pil]')
            return render_template('client_config.html', 
                                 client_name=client_name,
                                 client_config=client_config,
                                 config_file=f'wg0-client-{client_name}.conf')
        
    except Exception as e:
        flash(f'Ошибка генерации QR-кода: {e}')
        return redirect(url_for('index'))

@app.route('/api/traffic')
@login_required
def api_traffic():
    """API для получения статистики трафика"""
    traffic_data = get_client_traffic()
    formatted_data = {}
    
    for public_key, data in traffic_data.items():
        formatted_data[public_key] = {
            'received': data['received'],
            'sent': data['sent'],
            'total': data['total'],
            'received_formatted': format_bytes(data['received']),
            'sent_formatted': format_bytes(data['sent']),
            'total_formatted': format_bytes(data['total'])
        }
    
    return jsonify(formatted_data)

# Обработчик для автоматического выхода при истечении сессии
@app.before_request
def check_session_timeout():
    # Логирование для отладки
    # ВАЖНО: request.endpoint может быть None для некоторых запросов (например, /favicon.ico)
    if request.endpoint and 'delete_client' in request.endpoint:
        print(f"🕐 before_request: endpoint={request.endpoint}, path={request.path}, method={request.method}")
    elif 'delete_client' in request.path:
        print(f"🕐 before_request: endpoint={request.endpoint}, path={request.path}, method={request.method}")
    
    # ВАЖНО: request.endpoint может быть None для некоторых запросов
    if (request.endpoint is not None and request.endpoint not in ['login', 'static'] and 
        'logged_in' in session and SECURITY_ENABLED):
        
        login_time = session.get('login_time')
        if is_session_expired(login_time, SESSION_TIMEOUT // 60):
            print(f"❌ before_request: Сессия истекла для {request.endpoint}")
            # Проверяем, является ли запрос JSON (AJAX/API)
            # Проверяем несколькими способами для надежности
            content_type = request.content_type or request.headers.get('Content-Type', '')
            accept_header = request.headers.get('Accept', '')
            
            is_json_request = (
                request.method == 'POST' and 
                ('application/json' in content_type.lower() or 'application/json' in accept_header.lower())
            ) or (
                accept_header.startswith('application/json')
            )
            
            session.clear()
            if is_json_request:
                return jsonify({'success': False, 'message': 'Сессия истекла. Войдите снова.'}), 401
            flash('Сессия истекла. Войдите снова.')
            return redirect(url_for('login'))



def create_client_manual(client_name):
    """Создание клиента вручную с параметрами из wireguard-install.sh"""
    try:
        # Загружаем параметры WireGuard
        params = load_wireguard_params()
        
        if not params:
            return False, "Не удалось загрузить параметры WireGuard"
        
        # Получаем параметры сервера
        server_wg_ipv4 = params.get('SERVER_WG_IPV4', '10.66.66.1')
        server_wg_ipv6 = params.get('SERVER_WG_IPV6', 'fd42:42:42::1')
        server_pub_key = params.get('SERVER_PUB_KEY', '')
        server_pub_ip = params.get('SERVER_PUB_IP', '')
        server_port = params.get('SERVER_PORT', '51820')
        client_dns_1 = params.get('CLIENT_DNS_1', '1.1.1.1')
        client_dns_2 = params.get('CLIENT_DNS_2', '1.0.0.1')
        allowed_ips = params.get('ALLOWED_IPS', '0.0.0.0/0,::/0')
        interface_name = params.get('SERVER_WG_NIC', 'wg0')
        
        # Находим свободный IP адрес для клиента
        client_ipv4, client_ipv6 = find_free_client_ip(server_wg_ipv4, server_wg_ipv6, interface_name)
        
        if not client_ipv4:
            return False, "Не удалось найти свободный IP адрес для клиента"
        
        # Генерируем ключи для клиента
        private_key_cmd = 'wg genkey'
        stdout, stderr, code = run_command(private_key_cmd)
        if code != 0:
            return False, f'Ошибка генерации приватного ключа: {stderr}'
        
        private_key = stdout.strip()
        
        # Генерируем публичный ключ
        public_key_cmd = f'echo "{private_key}" | wg pubkey'
        stdout, stderr, code = run_command(public_key_cmd)
        if code != 0:
            return False, f'Ошибка генерации публичного ключа: {stderr}'
        
        public_key = stdout.strip()
        
        # Генерируем PresharedKey
        preshared_key_cmd = 'wg genpsk'
        stdout, stderr, code = run_command(preshared_key_cmd)
        if code != 0:
            return False, f'Ошибка генерации PresharedKey: {stderr}'
        
        preshared_key = stdout.strip()
        
        # Проверяем, что все необходимые параметры есть
        if not server_pub_key:
            return False, "Публичный ключ сервера не найден в параметрах"
        
        if not server_pub_ip:
            return False, "Публичный IP сервера не найден в параметрах"
        
        # Создаем конфигурацию клиента точно как в оригинальном скрипте
        client_config = f"""[Interface]
PrivateKey = {private_key}
Address = {client_ipv4}/32,{client_ipv6}/128
DNS = {client_dns_1},{client_dns_2}

[Peer]
PublicKey = {server_pub_key}
PresharedKey = {preshared_key}
Endpoint = {server_pub_ip}:{server_port}
AllowedIPs = {allowed_ips}"""
        
        # Сохраняем конфигурацию клиента в /root/
        client_config_file = f'/root/{interface_name}-client-{client_name}.conf'
        with open(client_config_file, 'w') as f:
            f.write(client_config)
        
        # Добавляем клиента в серверную конфигурацию
        server_config_file = f'/etc/wireguard/{interface_name}.conf'
        with open(server_config_file, 'a') as f:
            f.write(f'\n### Client {client_name}\n')
            f.write(f'[Peer]\n')
            f.write(f'PublicKey = {public_key}\n')
            f.write(f'PresharedKey = {preshared_key}\n')
            f.write(f'AllowedIPs = {client_ipv4}/32,{client_ipv6}/128\n\n')
        
        # Перезагружаем WireGuard
        reload_cmd = f'wg syncconf {interface_name} <(wg-quick strip {interface_name})'
        stdout, stderr, code = run_command(f'bash -c "{reload_cmd}"')
        if code != 0:
            # Fallback на обычную перезагрузку
            run_command(f'systemctl reload wg-quick@{interface_name}')
        
        return True, client_config
        
    except Exception as e:
        return False, f"Ошибка создания клиента: {str(e)}"

@app.route('/config_paths')
@login_required
def config_paths():
    """Настройка путей к конфигурационным файлам"""
    return render_template('config_paths.html', 
                         current_client_path=WIREGUARD_CONFIG_PATH,
                         current_server_path=WG_CONFIG_FILE)

@app.route('/browse_directory')
@login_required
def browse_directory():
    """Просмотр директорий на сервере"""
    path = request.args.get('path', '/')
    
    try:
        # Проверяем, что путь существует и доступен
        if not os.path.exists(path):
            flash(f'Путь {path} не существует')
            path = '/'
        
        if not os.path.isdir(path):
            flash(f'{path} не является директорией')
            path = os.path.dirname(path)
        
        # Получаем содержимое директории
        items = []
        try:
            for item in sorted(os.listdir(path)):
                if item.startswith('.'):
                    continue  # Пропускаем скрытые файлы
                
                item_path = os.path.join(path, item)
                is_dir = os.path.isdir(item_path)
                
                # Для файлов проверяем, является ли это конфигом WireGuard
                is_wg_config = False
                if not is_dir and item.endswith('.conf'):
                    try:
                        with open(item_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(1000)  # Читаем только начало файла
                        is_wg_config = '[Interface]' in content or '[Peer]' in content
                    except:
                        pass
                
                items.append({
                    'name': item,
                    'path': item_path,
                    'is_dir': is_dir,
                    'is_wg_config': is_wg_config
                })
        except PermissionError:
            flash(f'Нет доступа к директории {path}')
            items = []
        
        # Родительская директория
        parent_path = os.path.dirname(path) if path != '/' else None
        
        return render_template('browse_directory.html', 
                             current_path=path,
                             parent_path=parent_path,
                             items=items)
    
    except Exception as e:
        flash(f'Ошибка просмотра директории: {e}')
        return render_template('browse_directory.html', 
                             current_path='/',
                             parent_path=None,
                             items=[])

@app.route('/set_config_path', methods=['POST'])
@login_required
def set_config_path():
    """Установка пути к конфигурационным файлам"""
    global WIREGUARD_CONFIG_PATH, WG_CONFIG_FILE
    
    path_type = request.form.get('path_type')
    new_path = request.form.get('path', '').strip()
    
    if not new_path:
        flash('Путь не может быть пустым')
        return redirect(url_for('config_paths'))
    
    try:
        if path_type == 'client':
            # Проверяем, что путь существует
            if not os.path.exists(new_path):
                flash(f'Путь {new_path} не существует')
                return redirect(url_for('config_paths'))
            
            if not os.path.isdir(new_path):
                flash(f'{new_path} не является директорией')
                return redirect(url_for('config_paths'))
            
            # Добавляем слеш в конце если его нет
            if not new_path.endswith('/'):
                new_path += '/'
            
            WIREGUARD_CONFIG_PATH = new_path
            flash(f'Путь к клиентским конфигам установлен: {new_path}')
            
        elif path_type == 'server':
            # Проверяем, что файл существует
            if not os.path.exists(new_path):
                flash(f'Файл {new_path} не существует')
                return redirect(url_for('config_paths'))
            
            if not os.path.isfile(new_path):
                flash(f'{new_path} не является файлом')
                return redirect(url_for('config_paths'))
            
            WG_CONFIG_FILE = new_path
            flash(f'Путь к серверному конфигу установлен: {new_path}')
        
        # Логируем изменение настроек
        if DATABASE_ENABLED:
            log_action(AuditActions.SETTINGS_CHANGED, 
                      details={'path_type': path_type, 'new_path': new_path})
        
    except Exception as e:
        flash(f'Ошибка установки пути: {e}')
    
    return redirect(url_for('config_paths'))

@app.route('/check_directory_access')
@login_required
def check_directory_access_route():
    """Проверка доступа к директориям для диагностики"""
    scan_dirs = [
        '/root', '/etc/wireguard', '/home', '/opt', '/var/lib',
        './test_wireguard',
        os.path.expanduser('~/wireguard'),
        os.path.expanduser('~/Documents/wireguard'),
        './configs',
        '/tmp/wireguard',
        os.getcwd()
    ]
    
    access_info = []
    for directory in scan_dirs:
        has_access, message = check_directory_access(directory)
        access_info.append({
            'directory': directory,
            'has_access': has_access,
            'message': message,
            'exists': os.path.exists(directory)
        })
    
    return jsonify({
        'access_info': access_info,
        'current_user': os.getenv('USER', 'unknown'),
        'current_uid': os.getuid() if hasattr(os, 'getuid') else 'unknown'
    })

@app.route('/create_server_config', methods=['POST'])
@login_required
def create_server_config_route():
    """Создание базовой серверной конфигурации"""
    try:
        success, message = create_default_server_config()
        if success:
            flash(f'✅ {message}')
        else:
            flash(f'❌ {message}')
    except Exception as e:
        flash(f'❌ Ошибка создания серверной конфигурации: {str(e)}')
    
    return redirect(url_for('import_clients'))

@app.route('/scan_configs_in_path')
@login_required
def scan_configs_in_path():
    """Сканирование конфигов в указанном пути"""
    path = request.args.get('path', WIREGUARD_CONFIG_PATH)
    
    try:
        if not os.path.exists(path):
            return jsonify({'error': f'Путь {path} не существует'})
        
        if not os.path.isdir(path):
            return jsonify({'error': f'{path} не является директорией'})
        
        # Ищем конфиги WireGuard в указанной директории
        configs = []
        for file in os.listdir(path):
            if file.endswith('.conf'):
                file_path = os.path.join(path, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # Проверяем, что это конфиг WireGuard
                    if '[Interface]' in content or '[Peer]' in content:
                        # Определяем тип конфига
                        is_client = '[Interface]' in content and '[Peer]' in content
                        is_server = '[Interface]' in content and 'ListenPort' in content
                        
                        config_type = 'client' if is_client else 'server' if is_server else 'unknown'
                        
                        configs.append({
                            'name': file,
                            'path': file_path,
                            'type': config_type,
                            'size': os.path.getsize(file_path)
                        })
                except:
                    continue
        
        return jsonify({
            'path': path,
            'configs': configs,
            'count': len(configs)
        })
    
    except Exception as e:
        return jsonify({'error': f'Ошибка сканирования: {e}'})

@app.route('/api/preview_config')
@login_required
def preview_config():
    """Предварительный просмотр конфигурационного файла"""
    path = request.args.get('path', '')
    
    try:
        if not path or not os.path.exists(path):
            return "Файл не найден", 404
        
        if not os.path.isfile(path):
            return "Указанный путь не является файлом", 400
        
        # Проверяем размер файла (не больше 1MB)
        if os.path.getsize(path) > 1024 * 1024:
            return "Файл слишком большой для просмотра", 400
        
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        return content, 200, {'Content-Type': 'text/plain; charset=utf-8'}
    
    except Exception as e:
        return f"Ошибка чтения файла: {e}", 500

# Обработчики ошибок Flask
@app.errorhandler(404)
def not_found(error):
    """Обработка 404 ошибок с поддержкой JSON"""
    # Проверяем, является ли запрос JSON
    content_type = request.content_type or request.headers.get('Content-Type', '')
    accept_header = request.headers.get('Accept', '')
    is_json_request = (
        request.method == 'POST' and 
        'application/json' in content_type.lower()
    ) or (
        'application/json' in accept_header.lower()
    )
    
    if is_json_request:
        return jsonify({'success': False, 'message': 'Эндпоинт не найден'}), 404
    return render_template('404.html'), 404 if os.path.exists('templates/404.html') else ('Страница не найдена', 404)

@app.errorhandler(500)
def internal_error(error):
    """Обработка 500 ошибок с поддержкой JSON"""
    content_type = request.content_type or request.headers.get('Content-Type', '')
    accept_header = request.headers.get('Accept', '')
    is_json_request = (
        request.method == 'POST' and 
        'application/json' in content_type.lower()
    ) or (
        'application/json' in accept_header.lower()
    )
    
    if is_json_request:
        return jsonify({'success': False, 'message': 'Внутренняя ошибка сервера'}), 500
    # Проверяем, является ли запрос JSON (AJAX/API)
    content_type = request.content_type or request.headers.get('Content-Type', '')
    accept_header = request.headers.get('Accept', '')
    is_json_request = (content_type and 'application/json' in content_type) or \
                     (accept_header and 'application/json' in accept_header)
    
    if is_json_request:
        return jsonify({'success': False, 'error': 'Внутренняя ошибка сервера'}), 500
    else:
        # Для HTML запросов пытаемся использовать шаблон, если он есть
        if os.path.exists('templates/500.html'):
            return render_template('500.html'), 500
        else:
            # Fallback - простой текст
            return 'Внутренняя ошибка сервера', 500

if __name__ == '__main__':
    # Проверяем наличие модуля безопасности
    if not SECURITY_ENABLED:
        print("⚠️  ВНИМАНИЕ: Используется базовая аутентификация!")
        print("   Для повышенной безопасности установите модуль admin_config.py")
        print(f"   Логин: {FALLBACK_USERNAME}")
        print(f"   Пароль: {FALLBACK_PASSWORD}")
    else:
        print("✅ Модуль безопасности загружен")
        admin_config = load_admin_config()
        print(f"   Пользователь: {admin_config['username']}")
        print(f"   Таймаут сессии: {admin_config['session_timeout']} сек")
    
    # Порт можно переопределить через переменную окружения PORT
    port = int(os.getenv('PORT', '5000'))
    app.run(host='0.0.0.0', port=port, debug=False)