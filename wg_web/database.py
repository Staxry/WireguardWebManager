#!/usr/bin/env python3
"""
База данных для WireGuard Web Management Interface
Использует SQLite для хранения данных клиентов, логов и настроек
"""

import sqlite3
import json
import os
from datetime import datetime, timedelta
from contextlib import contextmanager
from typing import List, Dict, Optional, Tuple

# Путь к базе данных
# Путь к корню проекта (на уровень выше пакета wg_web)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(PROJECT_ROOT, 'data')
DB_PATH = os.path.join(DB_DIR, 'wireguard_web.db')

def ensure_db_directory():
    """Создание директории для базы данных"""
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR, mode=0o750)

@contextmanager
def get_db_connection():
    """Контекстный менеджер для подключения к базе данных"""
    ensure_db_directory()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Для доступа к колонкам по имени
    try:
        yield conn
    finally:
        conn.close()

def init_database():
    """Инициализация базы данных и создание таблиц"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Таблица клиентов
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                public_key TEXT,
                private_key TEXT,
                preshared_key TEXT,
                ip_address TEXT,
                dns_servers TEXT,
                endpoint TEXT,
                allowed_ips TEXT DEFAULT '0.0.0.0/0',
                persistent_keepalive INTEGER DEFAULT 25,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_handshake TIMESTAMP,
                status TEXT DEFAULT 'active',
                notes TEXT,
                group_name TEXT DEFAULT 'default',
                bandwidth_limit INTEGER DEFAULT 0,
                data_limit INTEGER DEFAULT 0,
                expiry_date TIMESTAMP
            )
        ''')
        
        # Таблица статистики трафика
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_name TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                bytes_received INTEGER DEFAULT 0,
                bytes_sent INTEGER DEFAULT 0,
                packets_received INTEGER DEFAULT 0,
                packets_sent INTEGER DEFAULT 0,
                FOREIGN KEY (client_name) REFERENCES clients (name) ON DELETE CASCADE
            )
        ''')
        
        # Таблица групп клиентов
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS client_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                dns_servers TEXT DEFAULT '8.8.8.8,1.1.1.1',
                bandwidth_limit INTEGER DEFAULT 0,
                data_limit INTEGER DEFAULT 0,
                allowed_ips TEXT DEFAULT '0.0.0.0/0',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Таблица настроек
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                description TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Таблица сессий
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Таблица API ключей
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id TEXT UNIQUE NOT NULL,
                api_key TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                permissions TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP,
                usage_count INTEGER DEFAULT 0,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Индексы для оптимизации
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_clients_name ON clients (name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_clients_status ON clients (status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_traffic_client_time ON traffic_stats (client_name, timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions (is_active, expires_at)')
        
        # Создаем группу по умолчанию
        cursor.execute('''
            INSERT OR IGNORE INTO client_groups (name, description)
            VALUES ('default', 'Группа по умолчанию для новых клиентов')
        ''')
        
        conn.commit()
        print("База данных инициализирована успешно")

class ClientDB:
    """Класс для работы с клиентами в базе данных"""
    
    @staticmethod
    def create_client(name: str, public_key: str = None, private_key: str = None, 
                     ip_address: str = None, **kwargs) -> bool:
        """Создание нового клиента"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Подготавливаем данные
                data = {
                    'name': name,
                    'public_key': public_key,
                    'private_key': private_key,
                    'ip_address': ip_address,
                    'preshared_key': kwargs.get('preshared_key'),
                    'dns_servers': kwargs.get('dns_servers', '8.8.8.8,1.1.1.1'),
                    'endpoint': kwargs.get('endpoint'),
                    'allowed_ips': kwargs.get('allowed_ips', '0.0.0.0/0'),
                    'persistent_keepalive': kwargs.get('persistent_keepalive', 25),
                    'notes': kwargs.get('notes'),
                    'group_name': kwargs.get('group_name', 'default'),
                    'bandwidth_limit': kwargs.get('bandwidth_limit', 0),
                    'data_limit': kwargs.get('data_limit', 0),
                    'expiry_date': kwargs.get('expiry_date')
                }
                
                cursor.execute('''
                    INSERT INTO clients (
                        name, public_key, private_key, ip_address, preshared_key,
                        dns_servers, endpoint, allowed_ips, persistent_keepalive,
                        notes, group_name, bandwidth_limit, data_limit, expiry_date
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    data['name'], data['public_key'], data['private_key'],
                    data['ip_address'], data['preshared_key'], data['dns_servers'],
                    data['endpoint'], data['allowed_ips'], data['persistent_keepalive'],
                    data['notes'], data['group_name'], data['bandwidth_limit'],
                    data['data_limit'], data['expiry_date']
                ))
                
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            return False  # Клиент уже существует
        except Exception as e:
            print(f"Ошибка создания клиента: {e}")
            return False
    
    @staticmethod
    def get_client(name: str) -> Optional[Dict]:
        """Получение клиента по имени"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM clients WHERE name = ?', (name,))
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            print(f"Ошибка получения клиента: {e}")
            return None
    
    @staticmethod
    def get_all_clients(group_name: str = None, status: str = None) -> List[Dict]:
        """Получение всех клиентов с фильтрацией"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                query = 'SELECT * FROM clients WHERE 1=1'
                params = []
                
                if group_name:
                    query += ' AND group_name = ?'
                    params.append(group_name)
                
                if status:
                    query += ' AND status = ?'
                    params.append(status)
                
                query += ' ORDER BY created_at DESC'
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            print(f"Ошибка получения клиентов: {e}")
            return []
    
    @staticmethod
    def update_client(name: str, **kwargs) -> bool:
        """Обновление данных клиента"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Формируем запрос обновления
                set_clauses = []
                params = []
                
                for key, value in kwargs.items():
                    if key in ['public_key', 'private_key', 'ip_address', 'preshared_key',
                              'dns_servers', 'endpoint', 'allowed_ips', 'persistent_keepalive',
                              'notes', 'group_name', 'bandwidth_limit', 'data_limit',
                              'expiry_date', 'status', 'last_handshake']:
                        set_clauses.append(f'{key} = ?')
                        params.append(value)
                
                if not set_clauses:
                    return False
                
                set_clauses.append('updated_at = CURRENT_TIMESTAMP')
                params.append(name)
                
                query = f'UPDATE clients SET {", ".join(set_clauses)} WHERE name = ?'
                cursor.execute(query, params)
                conn.commit()
                
                return cursor.rowcount > 0
        except Exception as e:
            print(f"Ошибка обновления клиента: {e}")
            return False
    
    @staticmethod
    def delete_client(name: str) -> bool:
        """Удаление клиента"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM clients WHERE name = ?', (name,))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            print(f"Ошибка удаления клиента: {e}")
            return False
    
    @staticmethod
    def get_client_stats(name: str, days: int = 30) -> Dict:
        """Получение статистики клиента"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Статистика за период
                cursor.execute('''
                    SELECT 
                        SUM(bytes_received) as total_received,
                        SUM(bytes_sent) as total_sent,
                        COUNT(*) as records_count,
                        MIN(timestamp) as first_record,
                        MAX(timestamp) as last_record
                    FROM traffic_stats 
                    WHERE client_name = ? AND timestamp >= datetime('now', '-{} days')
                '''.format(days), (name,))
                
                row = cursor.fetchone()
                if row:
                    return {
                        'total_received': row['total_received'] or 0,
                        'total_sent': row['total_sent'] or 0,
                        'total_traffic': (row['total_received'] or 0) + (row['total_sent'] or 0),
                        'records_count': row['records_count'],
                        'first_record': row['first_record'],
                        'last_record': row['last_record']
                    }
                return {}
        except Exception as e:
            print(f"Ошибка получения статистики: {e}")
            return {}

class TrafficDB:
    """Класс для работы со статистикой трафика"""
    
    @staticmethod
    def record_traffic(client_name: str, bytes_received: int, bytes_sent: int,
                      packets_received: int = 0, packets_sent: int = 0) -> bool:
        """Запись статистики трафика"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO traffic_stats 
                    (client_name, bytes_received, bytes_sent, packets_received, packets_sent)
                    VALUES (?, ?, ?, ?, ?)
                ''', (client_name, bytes_received, bytes_sent, packets_received, packets_sent))
                conn.commit()
                return True
        except Exception as e:
            print(f"Ошибка записи трафика: {e}")
            return False
    
    @staticmethod
    def get_traffic_history(client_name: str = None, hours: int = 24) -> List[Dict]:
        """Получение истории трафика"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                if client_name:
                    cursor.execute('''
                        SELECT * FROM traffic_stats 
                        WHERE client_name = ? AND timestamp >= datetime('now', '-{} hours')
                        ORDER BY timestamp DESC
                    '''.format(hours), (client_name,))
                else:
                    cursor.execute('''
                        SELECT * FROM traffic_stats 
                        WHERE timestamp >= datetime('now', '-{} hours')
                        ORDER BY timestamp DESC
                    '''.format(hours))
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            print(f"Ошибка получения истории трафика: {e}")
            return []

class SettingsDB:
    """Класс для работы с настройками"""
    
    @staticmethod
    def get_setting(key: str, default_value: str = None) -> str:
        """Получение настройки"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
                row = cursor.fetchone()
                return row['value'] if row else default_value
        except Exception as e:
            print(f"Ошибка получения настройки: {e}")
            return default_value
    
    @staticmethod
    def set_setting(key: str, value: str, description: str = None) -> bool:
        """Установка настройки"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO settings (key, value, description, updated_at)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ''', (key, value, description))
                conn.commit()
                return True
        except Exception as e:
            print(f"Ошибка установки настройки: {e}")
            return False
    
    @staticmethod
    def get_all_settings() -> Dict[str, str]:
        """Получение всех настроек"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT key, value FROM settings')
                rows = cursor.fetchall()
                return {row['key']: row['value'] for row in rows}
        except Exception as e:
            print(f"Ошибка получения настроек: {e}")
            return {}

def migrate_from_files():
    """Миграция данных из файлов в базу данных"""
    print("Начинаем миграцию данных из файлов...")
    
    try:
        # Импортируем функцию парсинга из основного приложения
        import sys
        import importlib.util
        app_path = os.path.join(PROJECT_ROOT, 'app.py')
        if os.path.exists(app_path):
            spec = importlib.util.spec_from_file_location("app", app_path)
            app_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(app_module)
            clients = app_module.parse_wg_config()
            
            migrated_count = 0
            for client in clients:
                success = ClientDB.create_client(
                    name=client['name'],
                    public_key=client.get('public_key'),
                    ip_address=client.get('ip_address'),
                    preshared_key=client.get('preshared_key'),
                    endpoint=client.get('endpoint')
                )
                if success:
                    migrated_count += 1
            
            print(f"Мигрировано {migrated_count} клиентов")
        else:
            print("Файл app.py не найден")
    except Exception as e:
        print(f"Ошибка миграции: {e}")

def cleanup_old_data(days: int = 90):
    """Очистка старых данных"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Удаляем старую статистику трафика
            cursor.execute('''
                DELETE FROM traffic_stats 
                WHERE timestamp < datetime('now', '-{} days')
            '''.format(days))
            
            # Удаляем неактивные сессии
            cursor.execute('''
                DELETE FROM sessions 
                WHERE expires_at < datetime('now') OR is_active = 0
            ''')
            
            conn.commit()
            print(f"Очистка данных старше {days} дней завершена")
            
    except Exception as e:
        print(f"Ошибка очистки данных: {e}")

if __name__ == '__main__':
    # Инициализация и тестирование базы данных
    print("Инициализация базы данных...")
    init_database()
    
    # Тестирование
    print("Тестирование операций с клиентами...")
    
    # Создание тестового клиента
    success = ClientDB.create_client(
        name='test-client',
        public_key='test-public-key',
        ip_address='10.0.0.100'
    )
    print(f"Создание клиента: {'успешно' if success else 'ошибка'}")
    
    # Получение клиента
    client = ClientDB.get_client('test-client')
    print(f"Получение клиента: {client['name'] if client else 'не найден'}")
    
    # Получение всех клиентов
    all_clients = ClientDB.get_all_clients()
    print(f"Всего клиентов: {len(all_clients)}")
    
    # Удаление тестового клиента
    deleted = ClientDB.delete_client('test-client')
    print(f"Удаление клиента: {'успешно' if deleted else 'ошибка'}")
    
    print("Тестирование завершено!")

