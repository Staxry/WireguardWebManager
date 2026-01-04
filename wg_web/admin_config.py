#!/usr/bin/env python3
"""
Конфигурация администратора для WireGuard Web Management Interface
Этот файл содержит учетные данные администратора и настройки безопасности
"""

import os
import secrets
import hashlib
from datetime import datetime, timedelta

# Генерация случайного секретного ключа для Flask сессий
def generate_secret_key():
    """Генерирует случайный секретный ключ"""
    return secrets.token_hex(32)

# Хеширование пароля
def hash_password(password):
    """Создает хеш пароля с солью"""
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}:{password_hash.hex()}"

def verify_password(password, hashed):
    """Проверяет пароль против хеша"""
    try:
        salt, stored_hash = hashed.split(':')
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return password_hash.hex() == stored_hash
    except:
        return False

# Фиксированный хеш пароля для стабильности (пароль: admin123)
FIXED_PASSWORD_HASH = "fixed_salt_2024:8e81e4bc00dd2a9627bffe393cd9e887d55b58661e27f37e6c5b4d81fb36c471"

# Настройки администратора по умолчанию
DEFAULT_ADMIN_CONFIG = {
    'username': 'admin',
    'password_hash': FIXED_PASSWORD_HASH,  # Пароль: admin123
    'secret_key': 'wireguard-web-secret-key-2024',
    'session_timeout': 600,  # 10 минут в секундах
    'max_login_attempts': 5,
    'lockout_duration': 300,  # 5 минут блокировки после превышения попыток
}

# Путь к файлу конфигурации
CONFIG_FILE = '/etc/wireguard/admin_config.json'
# Путь к корню проекта (на уровень выше пакета wg_web)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FALLBACK_CONFIG_FILE = os.path.join(PROJECT_ROOT, '.admin_config.json')

def get_config_file_path():
    """Определяет путь к файлу конфигурации"""
    if os.access('/etc/wireguard/', os.W_OK):
        return CONFIG_FILE
    else:
        return FALLBACK_CONFIG_FILE

def load_admin_config():
    """Загружает конфигурацию администратора"""
    import json
    
    config_path = get_config_file_path()
    
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
                # Проверяем наличие всех необходимых ключей
                for key in DEFAULT_ADMIN_CONFIG:
                    if key not in config:
                        config[key] = DEFAULT_ADMIN_CONFIG[key]
                return config
        else:
            # Создаем конфигурацию по умолчанию
            save_admin_config(DEFAULT_ADMIN_CONFIG)
            return DEFAULT_ADMIN_CONFIG.copy()
    except Exception as e:
        print(f"Ошибка загрузки конфигурации администратора: {e}")
        return DEFAULT_ADMIN_CONFIG.copy()

def save_admin_config(config):
    """Сохраняет конфигурацию администратора"""
    import json
    
    config_path = get_config_file_path()
    
    try:
        # Создаем директорию если не существует
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        # Устанавливаем права доступа только для root
        os.chmod(config_path, 0o600)
        
        return True
    except Exception as e:
        print(f"Ошибка сохранения конфигурации администратора: {e}")
        return False

def change_admin_password(username, old_password, new_password):
    """Изменяет пароль администратора"""
    config = load_admin_config()
    
    if config['username'] != username:
        return False, "Неверное имя пользователя"
    
    if not verify_password(old_password, config['password_hash']):
        return False, "Неверный текущий пароль"
    
    if len(new_password) < 8:
        return False, "Пароль должен содержать минимум 8 символов"
    
    config['password_hash'] = hash_password(new_password)
    
    if save_admin_config(config):
        return True, "Пароль успешно изменен"
    else:
        return False, "Ошибка сохранения нового пароля"

def change_admin_username(current_username, password, new_username):
    """Изменяет имя пользователя администратора"""
    config = load_admin_config()
    
    if config['username'] != current_username:
        return False, "Неверное текущее имя пользователя"
    
    if not verify_password(password, config['password_hash']):
        return False, "Неверный пароль"
    
    if len(new_username) < 3:
        return False, "Имя пользователя должно содержать минимум 3 символа"
    
    if not new_username.replace('_', '').replace('-', '').isalnum():
        return False, "Имя пользователя может содержать только буквы, цифры, дефисы и подчеркивания"
    
    config['username'] = new_username
    
    if save_admin_config(config):
        return True, "Имя пользователя успешно изменено"
    else:
        return False, "Ошибка сохранения нового имени пользователя"

def is_session_expired(login_time, timeout_minutes=10):
    """Проверяет, истекла ли сессия"""
    if not login_time:
        return True
    
    try:
        login_dt = datetime.fromisoformat(login_time)
        return datetime.now() - login_dt > timedelta(minutes=timeout_minutes)
    except:
        return True

# Система блокировки после неудачных попыток входа
LOGIN_ATTEMPTS = {}

def record_failed_login(ip_address):
    """Записывает неудачную попытку входа"""
    now = datetime.now()
    if ip_address not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[ip_address] = []
    
    LOGIN_ATTEMPTS[ip_address].append(now)
    
    # Удаляем старые попытки (старше часа)
    LOGIN_ATTEMPTS[ip_address] = [
        attempt for attempt in LOGIN_ATTEMPTS[ip_address]
        if now - attempt < timedelta(hours=1)
    ]

def is_ip_blocked(ip_address):
    """Проверяет, заблокирован ли IP адрес"""
    config = load_admin_config()
    max_attempts = config.get('max_login_attempts', 5)
    lockout_duration = config.get('lockout_duration', 300)
    
    if ip_address not in LOGIN_ATTEMPTS:
        return False
    
    now = datetime.now()
    recent_attempts = [
        attempt for attempt in LOGIN_ATTEMPTS[ip_address]
        if now - attempt < timedelta(seconds=lockout_duration)
    ]
    
    return len(recent_attempts) >= max_attempts

def clear_login_attempts(ip_address):
    """Очищает записи о неудачных попытках входа для IP"""
    if ip_address in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[ip_address] = []

# Инициализация конфигурации при импорте модуля
if __name__ == "__main__":
    # Создание начальной конфигурации
    config = load_admin_config()
    print("Конфигурация администратора:")
    print(f"- Имя пользователя: {config['username']}")
    print(f"- Файл конфигурации: {get_config_file_path()}")
    print(f"- Таймаут сессии: {config['session_timeout']} секунд")
    print(f"- Максимум попыток входа: {config['max_login_attempts']}")
    print(f"- Время блокировки: {config['lockout_duration']} секунд")
    print("\n⚠️  ВАЖНО: Измените пароль по умолчанию!")

