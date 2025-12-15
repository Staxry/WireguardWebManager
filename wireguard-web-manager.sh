#!/bin/bash

# WireGuard Web Management Interface - Менеджер приложения
# Версия: 3.1
# Автор: Enhanced Security Edition
# Описание: Комплексный скрипт для управления WireGuard веб-интерфейсом
# Особенности: Приложение запускается от имени root для полного доступа к WireGuard

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Конфигурация
APP_NAME="WireGuard Web Interface"
SERVICE_NAME="wireguard-web"
INSTALL_DIR="/opt/wireguard-web"
LOG_DIR="/var/log/wireguard-web"
CONFIG_DIR="/etc/wireguard-web"
NGINX_CONFIG="/etc/nginx/sites-available/wireguard-web"
SYSTEMD_SERVICE="/etc/systemd/system/wireguard-web.service"
APP_USER="wireguard-web"
VENV_PATH="$INSTALL_DIR/venv"
APP_LOG="$LOG_DIR/app.log"
ERROR_LOG="$LOG_DIR/error.log"
ACCESS_LOG="$LOG_DIR/access.log"
BLOCKED_IPS_FILE="$LOG_DIR/blocked_ips.json"

# Переменные для SSL
DOMAIN_NAME=""
USE_LETSENCRYPT=false

# Функции для вывода
print_header() {
    echo -e "${WHITE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}║${CYAN}                    $1${WHITE}                    ║${NC}"
    echo -e "${WHITE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo
}

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_separator() {
    echo -e "${PURPLE}────────────────────────────────────────────────────────────────────────────────${NC}"
}

# Проверка прав root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Этот скрипт должен быть запущен от имени root"
        print_status "Используйте: sudo $0 $1"
        exit 1
    fi
}

# Проверка операционной системы
check_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        print_error "Не удалось определить операционную систему"
        exit 1
    fi
}

# Установка зависимостей
install_dependencies() {
    print_status "Установка системных зависимостей..."
    
    check_os
    
    if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
        apt update -qq
        apt install -y python3 python3-pip python3-venv nginx expect sqlite3 curl wget net-tools htop
    elif [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]] || [[ "$OS" == *"Rocky"* ]] || [[ "$OS" == *"AlmaLinux"* ]]; then
        yum update -y -q
        yum install -y python3 python3-pip nginx expect sqlite curl wget net-tools htop
    elif [[ "$OS" == *"Fedora"* ]]; then
        dnf update -y -q
        dnf install -y python3 python3-pip nginx expect sqlite curl wget net-tools htop
    else
        print_warning "Неподдерживаемая ОС: $OS"
        print_warning "Попробуйте установить зависимости вручную:"
        print_warning "python3, python3-pip, python3-venv, nginx, expect, sqlite3"
        read -p "Продолжить установку? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    print_success "Системные зависимости установлены"
}

# Создание пользователя для приложения (теперь используем root)
create_app_user() {
    print_status "Настройка пользователя для приложения..."
    
    # Создаем резервного пользователя для возможного использования в будущем
    if ! id "$APP_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$INSTALL_DIR" "$APP_USER"
        print_success "Резервный пользователь $APP_USER создан"
    else
        print_warning "Пользователь $APP_USER уже существует"
    fi
    
    # Добавляем пользователя в группу wireguard для доступа к конфигурациям
    if ! getent group wireguard >/dev/null; then
        groupadd wireguard
        print_success "Группа wireguard создана"
    fi
    
    # Добавляем root в группу wireguard (на всякий случай)
    usermod -a -G wireguard root 2>/dev/null || true
    
    print_success "Приложение будет запускаться от имени root с полными правами доступа"
}

# Создание директорий
create_directories() {
    print_status "Создание директорий..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p /etc/nginx/ssl
    
    # Копирование файлов приложения
    if [[ -f "app.py" ]]; then
        print_status "Копирование файлов приложения..."
        cp -r . "$INSTALL_DIR/"
        
        # Удаляем ненужные файлы
        rm -f "$INSTALL_DIR/wireguard-web-manager.sh"
        rm -rf "$INSTALL_DIR/.git" 2>/dev/null || true
        rm -rf "$INSTALL_DIR/__pycache__" 2>/dev/null || true
        rm -f "$INSTALL_DIR"/*.pyc 2>/dev/null || true
        
        # Установка прав для root (приложение будет запускаться от root)
        chown -R root:root "$INSTALL_DIR"
        chown -R root:root "$LOG_DIR"
        chown -R root:root "$CONFIG_DIR"
        
        # Устанавливаем правильные права доступа
        chmod -R 755 "$INSTALL_DIR"
        chmod -R 755 "$LOG_DIR"
        chmod -R 700 "$CONFIG_DIR"  # Более строгие права для конфигурации
        
        # Делаем основные файлы исполняемыми
        chmod +x "$INSTALL_DIR/app.py"
        
        print_success "Файлы приложения скопированы с правами root"
    else
        print_error "Файлы приложения не найдены в текущей директории"
        print_error "Запустите скрипт из директории с app.py"
        exit 1
    fi
}

# Установка Python зависимостей
install_python_deps() {
    print_status "Установка Python зависимостей..."
    
    cd "$INSTALL_DIR"
    
    # Создание виртуального окружения
    python3 -m venv venv
    source venv/bin/activate
    
    # Обновление pip
    pip install --upgrade pip -q
    
    # Установка зависимостей
    if [[ -f "requirements.txt" ]]; then
        # Проверяем, есть ли в файле реальные зависимости (не только комментарии)
        if grep -v '^#' requirements.txt | grep -v '^$' | grep -q .; then
            pip install -r requirements.txt -q
            print_success "Python зависимости установлены из requirements.txt"
        else
            print_warning "requirements.txt содержит только комментарии, устанавливаем базовые зависимости"
            pip install Flask==2.3.3 Werkzeug==2.3.7 qrcode[pil]==7.4.2 Pillow==10.0.1 -q
        fi
    else
        print_warning "requirements.txt не найден, устанавливаем базовые зависимости"
        pip install Flask==2.3.3 Werkzeug==2.3.7 qrcode[pil]==7.4.2 Pillow==10.0.1 -q
    fi
    
    deactivate
}

# Настройка конфигурации
setup_config() {
    print_status "Настройка конфигурации..."
    
    # Генерация секретного ключа
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    
    # Генерация хеша пароля по умолчанию
    DEFAULT_PASSWORD="admin123"
    SALT=$(python3 -c "import secrets; print(secrets.token_hex(16))")
    PASSWORD_HASH=$(python3 -c "
import hashlib
import hmac
password = '$DEFAULT_PASSWORD'
salt = '$SALT'
hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
print(f'{salt}:{hash_obj.hex()}')
")
    
    # Создание конфигурационного файла
    cat > "$CONFIG_DIR/admin_config.json" << EOF
{
  "username": "admin",
  "password_hash": "$PASSWORD_HASH",
  "secret_key": "$SECRET_KEY",
  "session_timeout": 600,
  "max_login_attempts": 5,
  "lockout_duration": 300
}
EOF
    
    chmod 600 "$CONFIG_DIR/admin_config.json"
    chown root:root "$CONFIG_DIR/admin_config.json"
    
    # Создание символической ссылки для совместимости
    ln -sf "$CONFIG_DIR/admin_config.json" "$INSTALL_DIR/.admin_config.json"
    chown -h root:root "$INSTALL_DIR/.admin_config.json"
    
    print_success "Конфигурация создана"
    export DEFAULT_PASSWORD
}

# Настройка прав доступа к WireGuard
setup_wireguard_permissions() {
    print_status "Настройка прав доступа к WireGuard..."
    
    # Создаем директории WireGuard если они не существуют
    mkdir -p /etc/wireguard
    mkdir -p /root
    
    # Устанавливаем правильные права на директории WireGuard
    chown -R root:root /etc/wireguard
    chmod -R 700 /etc/wireguard
    
    # Убеждаемся, что root имеет доступ к своей домашней директории
    chown root:root /root
    chmod 700 /root
    
    # Создаем тестовую директорию для конфигураций если её нет
    if [[ ! -d "$INSTALL_DIR/test_wireguard" ]]; then
        mkdir -p "$INSTALL_DIR/test_wireguard"
        chown root:root "$INSTALL_DIR/test_wireguard"
        chmod 755 "$INSTALL_DIR/test_wireguard"
    fi
    
    print_success "Права доступа к WireGuard настроены"
}

# Исправление прав доступа (отдельная функция)
fix_permissions() {
    print_header "ИСПРАВЛЕНИЕ ПРАВ ДОСТУПА"
    
    check_root "fix-permissions"
    
    print_status "Исправление прав доступа для WireGuard Web Interface..."
    
    # Исправляем права на директории приложения
    if [[ -d "$INSTALL_DIR" ]]; then
        print_status "Исправление прав на $INSTALL_DIR..."
        chown -R root:root "$INSTALL_DIR"
        chmod -R 755 "$INSTALL_DIR"
        chmod +x "$INSTALL_DIR/app.py"
        print_success "Права на директорию приложения исправлены"
    fi
    
    # Исправляем права на логи
    if [[ -d "$LOG_DIR" ]]; then
        print_status "Исправление прав на $LOG_DIR..."
        chown -R root:root "$LOG_DIR"
        chmod -R 755 "$LOG_DIR"
        print_success "Права на директорию логов исправлены"
    fi
    
    # Исправляем права на конфигурацию
    if [[ -d "$CONFIG_DIR" ]]; then
        print_status "Исправление прав на $CONFIG_DIR..."
        chown -R root:root "$CONFIG_DIR"
        chmod -R 700 "$CONFIG_DIR"
        print_success "Права на директорию конфигурации исправлены"
    fi
    
    # Настраиваем права WireGuard
    setup_wireguard_permissions
    
    # Перезапускаем сервис если он запущен
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_status "Перезапуск сервиса с новыми правами..."
        systemctl restart "$SERVICE_NAME"
        sleep 2
        
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            print_success "Сервис успешно перезапущен"
        else
            print_error "Ошибка перезапуска сервиса"
            print_status "Проверьте логи: journalctl -u $SERVICE_NAME -f"
        fi
    fi
    
    print_success "Права доступа исправлены"
}

# Создание systemd сервиса
create_systemd_service() {
    print_status "Создание systemd сервиса с правами администратора..."
    
    cat > "$SYSTEMD_SERVICE" << EOF
[Unit]
Description=WireGuard Web Management Interface
After=network.target wireguard.service
Wants=network.target
Requires=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$VENV_PATH/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=FLASK_APP=app.py
Environment=FLASK_ENV=production
Environment=PYTHONPATH=$INSTALL_DIR
ExecStart=$VENV_PATH/bin/python app.py
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3
TimeoutStopSec=10
KillMode=mixed
KillSignal=SIGTERM

# Логирование
StandardOutput=append:$APP_LOG
StandardError=append:$ERROR_LOG

# Права доступа для WireGuard
ReadWritePaths=$LOG_DIR $CONFIG_DIR /etc/wireguard /root /tmp /var/lib /opt
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_FOWNER
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

# Ограничения ресурсов
LimitNOFILE=65536
LimitNPROC=4096
LimitCORE=0

# Безопасность (менее строгая для root доступа)
NoNewPrivileges=false
PrivateTmp=false
ProtectSystem=false
ProtectHome=false

[Install]
WantedBy=multi-user.target
EOF
    
    # Устанавливаем правильные права на файлы
    chown -R root:root "$INSTALL_DIR"
    chown -R root:root "$LOG_DIR"
    chown -R root:root "$CONFIG_DIR"
    
    # Делаем файлы исполняемыми
    chmod +x "$INSTALL_DIR/app.py"
    
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    
    print_success "Systemd сервис создан и включен с правами root"
}

# Настройка SSL сертификатов
setup_ssl() {
    print_status "Настройка SSL сертификатов..."
    
    # Создаем директорию для SSL
    mkdir -p /etc/nginx/ssl
    
    # Спрашиваем пользователя о типе сертификата
    echo
    echo -e "${CYAN}Выберите тип SSL сертификата:${NC}"
    echo "1) Let's Encrypt (бесплатный, требует домен)"
    echo "2) Самоподписанный (для IP адреса)"
    echo
    read -p "Ваш выбор (1-2): " ssl_choice
    
    case $ssl_choice in
        1)
            setup_letsencrypt
            ;;
        2)
            setup_selfsigned_cert
            ;;
        *)
            print_warning "Неверный выбор, используем самоподписанный сертификат"
            setup_selfsigned_cert
            ;;
    esac
}

# Настройка Let's Encrypt
setup_letsencrypt() {
    print_status "Настройка Let's Encrypt..."
    
    # Устанавливаем certbot
    if ! command -v certbot &> /dev/null; then
        print_status "Установка certbot..."
        if [[ -f /etc/debian_version ]]; then
            apt-get update
            apt-get install -y certbot python3-certbot-nginx
        elif [[ -f /etc/redhat-release ]]; then
            yum install -y certbot python3-certbot-nginx || dnf install -y certbot python3-certbot-nginx
        else
            print_error "Неподдерживаемая система для автоматической установки certbot"
            print_status "Установите certbot вручную и повторите попытку"
            setup_selfsigned_cert
            return
        fi
    fi
    
    # Запрашиваем домен
    echo
    read -p "Введите ваш домен (например, vpn.example.com): " domain_name
    
    if [[ -z "$domain_name" ]]; then
        print_error "Домен не указан, используем самоподписанный сертификат"
        setup_selfsigned_cert
        return
    fi
    
    # Проверяем, что домен указывает на этот сервер
    print_status "Проверка DNS записи для $domain_name..."
    server_ip=$(curl -s ifconfig.me || curl -s ipinfo.io/ip)
    domain_ip=$(dig +short "$domain_name" | tail -n1)
    
    if [[ "$server_ip" != "$domain_ip" ]]; then
        print_warning "DNS запись для $domain_name не указывает на этот сервер"
        print_status "IP сервера: $server_ip"
        print_status "IP домена: $domain_ip"
        echo
        read -p "Продолжить с Let's Encrypt? (y/N): " continue_le
        if [[ ! "$continue_le" =~ ^[Yy]$ ]]; then
            setup_selfsigned_cert
            return
        fi
    fi
    
    # Создаем временную конфигурацию Nginx для HTTP
    create_temp_nginx_config "$domain_name"
    
    # Получаем сертификат (плагин nginx или webroot fallback)
    print_status "Получение SSL сертификата от Let's Encrypt..."

    mkdir -p /var/www/html

    # Проверяем наличие плагина nginx у certbot
    if certbot plugins 2>/dev/null | grep -qi nginx; then
        HAS_NGINX_PLUGIN=true
    else
        HAS_NGINX_PLUGIN=false
        # Пытаемся установить плагин
        if [[ -f /etc/debian_version ]]; then
            apt-get update -y >/dev/null 2>&1 || true
            apt-get install -y python3-certbot-nginx >/dev/null 2>&1 || true
        elif [[ -f /etc/redhat-release ]]; then
            yum install -y certbot python3-certbot-nginx >/dev/null 2>&1 || dnf install -y certbot python3-certbot-nginx >/dev/null 2>&1 || true
        fi
        if certbot plugins 2>/dev/null | grep -qi nginx; then HAS_NGINX_PLUGIN=true; fi
    fi

    CERT_OK=false
    if [[ "$HAS_NGINX_PLUGIN" == "true" ]]; then
        if certbot --nginx -d "$domain_name" --non-interactive --agree-tos --email "admin@$domain_name" --redirect; then
            CERT_OK=true
        fi
    fi

    # Fallback на webroot, если плагина нет или не сработал
    if [[ "$CERT_OK" != "true" ]]; then
        print_warning "Плагин nginx недоступен или не сработал. Пробуем webroot..."
        if certbot certonly --webroot -w /var/www/html -d "$domain_name" --non-interactive --agree-tos --email "admin@$domain_name" --keep-until-expiring --quiet; then
            CERT_OK=true
        fi
    fi

    if [[ "$CERT_OK" == "true" ]]; then
        print_success "SSL сертификат успешно получен!"
        DOMAIN_NAME="$domain_name"
        USE_LETSENCRYPT=true
    else
        print_error "Не удалось получить сертификат Let's Encrypt"
        print_status "Используем самоподписанный сертификат"
        setup_selfsigned_cert
    fi
}

# Создание временной конфигурации Nginx для получения сертификата
create_temp_nginx_config() {
    local domain="$1"
    
    cat > /etc/nginx/sites-available/temp-wireguard << EOF
server {
    listen 80;
    server_name $domain;
    
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}
EOF
    
    ln -sf /etc/nginx/sites-available/temp-wireguard /etc/nginx/sites-enabled/temp-wireguard
    nginx -t && systemctl reload nginx
}

# Настройка самоподписанного сертификата
setup_selfsigned_cert() {
    print_status "Создание самоподписанного SSL сертификата..."
    
    # Получаем IP адрес сервера
    server_ip=$(curl -s ifconfig.me || curl -s ipinfo.io/ip || hostname -I | awk '{print $1}')
    
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/wireguard-web.key \
        -out /etc/nginx/ssl/wireguard-web.crt \
        -subj "/C=RU/ST=Moscow/L=Moscow/O=WireGuard-Web/CN=$server_ip" 2>/dev/null
    
    chmod 600 /etc/nginx/ssl/wireguard-web.key
    chmod 644 /etc/nginx/ssl/wireguard-web.crt
    
    print_success "Самоподписанный сертификат создан"
    print_warning "⚠️  Браузер покажет предупреждение о безопасности"
    print_status "Для доступа используйте: https://$server_ip"
}

# Добавление второго домена (отдельный конфиг и сертификат)
add_domain_for_existing_server() {
    print_header "ДОБАВЛЕНИЕ ВТОРОГО ДОМЕНА"

    # Установка certbot при необходимости
    if ! command -v certbot &> /dev/null; then
        print_status "Установка certbot..."
        if [[ -f /etc/debian_version ]]; then
            apt-get update
            apt-get install -y certbot python3-certbot-nginx
        elif [[ -f /etc/redhat-release ]]; then
            yum install -y certbot python3-certbot-nginx || dnf install -y certbot python3-certbot-nginx
        else
            print_error "Неподдерживаемая ОС для автоустановки certbot"
            return 1
        fi
    fi

    echo
    read -p "Введите домен второго сайта (например, panel.example.com): " second_domain
    if [[ -z "$second_domain" ]]; then
        print_error "Домен не указан"
        return 1
    fi

    # Проверка DNS
    print_status "Проверка DNS записи для $second_domain..."
    server_ip=$(curl -s ifconfig.me || curl -s ipinfo.io/ip)
    domain_ip=$(dig +short "$second_domain" | tail -n1)
    if [[ -n "$domain_ip" && -n "$server_ip" && "$server_ip" != "$domain_ip" ]]; then
        print_warning "DNS для $second_domain указывает на $domain_ip, а сервер имеет IP $server_ip"
        read -p "Все равно продолжить? (y/N): " cont
        if [[ ! "$cont" =~ ^[Yy]$ ]]; then
            return 1
        fi
    fi

    # Временная HTTP-конфигурация для валидации
    create_temp_nginx_config "$second_domain"

    # Запрашиваем сертификат и авто-SSL-настройку (с fallback на webroot)
    print_status "Получение сертификата Let's Encrypt для $second_domain..."

    mkdir -p /var/www/html

    if certbot plugins 2>/dev/null | grep -qi nginx; then
        HAS_NGINX_PLUGIN=true
    else
        HAS_NGINX_PLUGIN=false
        if [[ -f /etc/debian_version ]]; then
            apt-get update -y >/dev/null 2>&1 || true
            apt-get install -y python3-certbot-nginx >/dev/null 2>&1 || true
        elif [[ -f /etc/redhat-release ]]; then
            yum install -y certbot python3-certbot-nginx >/dev/null 2>&1 || dnf install -y certbot python3-certbot-nginx >/dev/null 2>&1 || true
        fi
        if certbot plugins 2>/dev/null | grep -qi nginx; then HAS_NGINX_PLUGIN=true; fi
    fi

    CERT_OK=false
    if [[ "$HAS_NGINX_PLUGIN" == "true" ]]; then
        if certbot --nginx -d "$second_domain" --non-interactive --agree-tos --email "admin@$second_domain" --redirect; then
            CERT_OK=true
        fi
    fi

    if [[ "$CERT_OK" != "true" ]]; then
        print_warning "Плагин nginx недоступен или не сработал. Пробуем webroot..."
        if certbot certonly --webroot -w /var/www/html -d "$second_domain" --non-interactive --agree-tos --email "admin@$second_domain" --keep-until-expiring --quiet; then
            CERT_OK=true
        fi
    fi

    if [[ "$CERT_OK" != "true" ]]; then
        print_error "Не удалось получить сертификат Let's Encrypt для $second_domain"
        print_status "Оставляем временную HTTP-конфигурацию без SSL"
        return 1
    fi

    # Готовим отдельный production-конфиг под домен
    domain_safe=${second_domain//./_}
    local conf_path="/etc/nginx/sites-available/wireguard-web-$domain_safe"
    local enabled_path="/etc/nginx/sites-enabled/wireguard-web-$domain_safe"

    # Уникальные зоны rate limit и upstream, чтобы исключить конфликты
    local z_login="login_$domain_safe"
    local z_api="api_$domain_safe"
    local z_general="general_$domain_safe"
    local upstream_name="wireguard_web_$domain_safe"

    cat > "$conf_path" << EOF
# Rate limiting zones (уникальные на домен)
limit_req_zone \$binary_remote_addr zone=$z_login:10m rate=5r/m;
limit_req_zone \$binary_remote_addr zone=$z_api:10m rate=30r/m;
limit_req_zone \$binary_remote_addr zone=$z_general:10m rate=60r/m;

# Upstream для приложения (уникальное имя)
upstream $upstream_name {
    server 127.0.0.1:5000 fail_timeout=5s max_fails=3;
}

# HTTP -> HTTPS редирект и ACME
server {
    listen 80;
    server_name $second_domain;

    server_tokens off;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

# HTTPS c сертификатом Let's Encrypt
server {
    listen 443 ssl http2;
    server_name $second_domain;

    server_tokens off;

    ssl_certificate /etc/letsencrypt/live/$second_domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$second_domain/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';" always;

    client_max_body_size 1M;
    client_body_timeout 10s;
    client_header_timeout 10s;

    access_log /var/log/nginx/wireguard-web-$domain_safe-access.log;
    error_log  /var/log/nginx/wireguard-web-$domain_safe-error.log;

    location / {
        limit_req zone=$z_general burst=20 nodelay;
        proxy_pass http://$upstream_name;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 5s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }

    location /login {
        limit_req zone=$z_login burst=3 nodelay;
        proxy_pass http://$upstream_name;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /api/ {
        limit_req zone=$z_api burst=10 nodelay;
        proxy_pass http://$upstream_name;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /static/ {
        alias $INSTALL_DIR/static/;
        expires 1d;
        add_header Cache-Control "public, immutable";
        location ~* \.js$ {
            add_header Content-Type application/javascript;
        }
        location ~* \.css$ {
            add_header Content-Type text/css;
        }
    }

    location ~ /\. { deny all; access_log off; log_not_found off; }
    location ~ \.(conf|json|py|sh|log)$ { deny all; access_log off; log_not_found off; }
}
EOF

    ln -sf "$conf_path" "$enabled_path"

    # Удаляем временный конфиг, если остался
    rm -f /etc/nginx/sites-enabled/temp-wireguard
    rm -f /etc/nginx/sites-available/temp-wireguard

    if nginx -t 2>/dev/null; then
        systemctl reload nginx
        print_success "Добавлен домен $second_domain и настроен отдельный конфиг Nginx"
    else
        print_error "Ошибка проверки конфигурации Nginx для домена $second_domain"
        nginx -t
        return 1
    fi
}

# Настройка Nginx
setup_nginx() {
    print_status "Настройка Nginx..."
    
    # Настраиваем SSL сертификаты
    setup_ssl
    
    # Создание конфигурации Nginx
    print_status "Создание конфигурации Nginx в $NGINX_CONFIG"
    print_status "Путь к статическим файлам: $INSTALL_DIR/static/"
    
    cat > "$NGINX_CONFIG" << EOF
# Rate limiting zones
limit_req_zone \$binary_remote_addr zone=login:10m rate=5r/m;
limit_req_zone \$binary_remote_addr zone=api:10m rate=30r/m;
limit_req_zone \$binary_remote_addr zone=general:10m rate=60r/m;

# Upstream для приложения
upstream wireguard_web {
    server 127.0.0.1:5000 fail_timeout=5s max_fails=3;
}

# HTTP -> HTTPS редирект
server {
    listen 80;
    server_name ${DOMAIN_NAME:-_};
    
    # Безопасность
    server_tokens off;
    
    # Для Let's Encrypt
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    
    # Редирект на HTTPS
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

# HTTPS сервер
server {
    listen 443 ssl http2;
    server_name ${DOMAIN_NAME:-_};
    
    # Безопасность
    server_tokens off;
    
    # SSL конфигурация
    ssl_certificate /etc/nginx/ssl/wireguard-web.crt;
    ssl_certificate_key /etc/nginx/ssl/wireguard-web.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    
    # Безопасность заголовков
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';" always;
    
    # Ограничения
    client_max_body_size 1M;
    client_body_timeout 10s;
    client_header_timeout 10s;
    
    # Логирование
    access_log /var/log/nginx/wireguard-web-access.log;
    error_log /var/log/nginx/wireguard-web-error.log;
    
    # Основное приложение
    location / {
        limit_req zone=general burst=20 nodelay;
        
        proxy_pass http://wireguard_web;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Таймауты
        proxy_connect_timeout 5s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
        
        # Буферизация
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }
    
    # Страница входа - строгие ограничения
    location /login {
        limit_req zone=login burst=3 nodelay;
        
        proxy_pass http://wireguard_web;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # API эндпоинты
    location /api/ {
        limit_req zone=api burst=10 nodelay;
        
        proxy_pass http://wireguard_web;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # Статические файлы
    location /static/ {
        alias $INSTALL_DIR/static/;
        expires 1d;
        add_header Cache-Control "public, immutable";
        
        # Правильные Content-Type для статических файлов
        location ~* \.js$ {
            add_header Content-Type application/javascript;
        }
        location ~* \.css$ {
            add_header Content-Type text/css;
        }
    }
    
    # Блокировка доступа к служебным файлам
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    location ~ \.(conf|json|py|sh|log)$ {
        deny all;
        access_log off;
        log_not_found off;
    }
}
EOF
    
    # Проверяем созданную конфигурацию
    print_status "Проверяем созданную конфигурацию..."
    if grep -q "install_dir" "$NGINX_CONFIG"; then
        print_error "Обнаружена неподставленная переменная install_dir в конфигурации!"
        print_status "Содержимое проблемной строки:"
        grep "install_dir" "$NGINX_CONFIG"
        exit 1
    fi
    
    # Удаляем временную конфигурацию если есть
    rm -f /etc/nginx/sites-enabled/temp-wireguard
    rm -f /etc/nginx/sites-available/temp-wireguard
    
    # Активация сайта
    ln -sf "$NGINX_CONFIG" /etc/nginx/sites-enabled/wireguard-web
    rm -f /etc/nginx/sites-enabled/default
    
    # Проверка конфигурации
    if nginx -t 2>/dev/null; then
        systemctl restart nginx
        systemctl enable nginx
        print_success "Nginx настроен и перезапущен"
    else
        print_error "Ошибка в конфигурации Nginx"
        nginx -t
        exit 1
    fi
}

# Настройка файрвола
setup_firewall() {
    print_status "Настройка файрвола..."
    
    if command -v ufw &> /dev/null; then
        ufw allow 80/tcp comment "HTTP for WireGuard Web"
        ufw allow 443/tcp comment "HTTPS for WireGuard Web"
        ufw --force enable
        print_success "UFW настроен"
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        firewall-cmd --reload
        print_success "Firewalld настроен"
    else
        print_warning "Файрвол не найден. Настройте порты 80 и 443 вручную"
    fi
}

# Инициализация базы данных
init_database() {
    print_status "Инициализация базы данных..."
    
    cd "$INSTALL_DIR"
    source venv/bin/activate
    
    python3 -c "
try:
    from database import init_database
    init_database()
    print('✅ База данных инициализирована')
except ImportError:
    print('⚠️  Модуль database не найден, пропускаем инициализацию')
except Exception as e:
    print(f'❌ Ошибка инициализации БД: {e}')
" 2>/dev/null || print_warning "База данных не инициализирована"
    
    deactivate
    
    # Установка прав на базу данных
    chown "$APP_USER:$APP_USER" "$INSTALL_DIR"/*.db 2>/dev/null || true
    
    print_success "База данных готова"
}

# Полная установка
install_app() {
    print_header "УСТАНОВКА $APP_NAME"
    
    check_root "install"
    
    print_status "Начинаем установку $APP_NAME..."
    print_separator
    
    install_dependencies
    print_separator
    
    create_app_user
    print_separator
    
    create_directories
    print_separator
    
    install_python_deps
    print_separator
    
    setup_config
    print_separator
    
    setup_wireguard_permissions
    print_separator
    
    create_systemd_service
    print_separator
    
    # Дополнительный вопрос перед установкой сертификатов/Nginx
    echo
    read -p "На сервере уже есть другое приложение на Nginx (другой сайт/домен)? (y/N): " has_other_app
    if [[ "$has_other_app" =~ ^[Yy]$ ]]; then
        add_domain_for_existing_server
        print_separator
    fi
    
    setup_nginx
    print_separator
    
    setup_firewall
    print_separator
    
    init_database
    print_separator
    
    # Запуск сервисов
    print_status "Запуск сервисов..."
    systemctl start "$SERVICE_NAME"
    
    print_separator
    
    # Проверка статуса
    sleep 3
    check_status_detailed
    
    print_separator
    print_installation_info
}

# Проверка статуса (подробная)
check_status_detailed() {
    print_header "СТАТУС $APP_NAME"
    
    local all_ok=true
    
    # Проверка systemd сервиса
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "✅ $SERVICE_NAME: Активен"
        
        # Дополнительная информация о сервисе
        local uptime=$(systemctl show "$SERVICE_NAME" --property=ActiveEnterTimestamp --value)
        local memory=$(systemctl show "$SERVICE_NAME" --property=MemoryCurrent --value)
        if [[ "$memory" != "[not set]" ]] && [[ -n "$memory" ]]; then
            memory=$((memory / 1024 / 1024))
            print_status "   Время работы: $(date -d "$uptime" '+%Y-%m-%d %H:%M:%S')"
            print_status "   Использование памяти: ${memory} MB"
        fi
    else
        print_error "❌ $SERVICE_NAME: Неактивен"
        all_ok=false
    fi
    
    # Проверка Nginx
    if systemctl is-active --quiet nginx; then
        print_success "✅ Nginx: Активен"
    else
        print_error "❌ Nginx: Неактивен"
        all_ok=false
    fi
    
    # Проверка портов
    if netstat -tlnp 2>/dev/null | grep -q ":443 "; then
        print_success "✅ HTTPS порт 443: Открыт"
    else
        print_warning "⚠️  HTTPS порт 443: Не найден"
        all_ok=false
    fi
    
    if netstat -tlnp 2>/dev/null | grep -q ":5000 "; then
        print_success "✅ Flask приложение: Запущено на порту 5000"
    else
        print_warning "⚠️  Flask приложение: Не найдено на порту 5000"
        all_ok=false
    fi
    
    # Проверка файлов
    if [[ -f "$INSTALL_DIR/app.py" ]]; then
        print_success "✅ Файлы приложения: Найдены"
    else
        print_error "❌ Файлы приложения: Не найдены"
        all_ok=false
    fi
    
    if [[ -f "$CONFIG_DIR/admin_config.json" ]]; then
        print_success "✅ Конфигурация: Найдена"
    else
        print_error "❌ Конфигурация: Не найдена"
        all_ok=false
    fi
    
    # Проверка логов
    if [[ -f "$APP_LOG" ]]; then
        local log_size=$(du -h "$APP_LOG" 2>/dev/null | cut -f1)
        print_success "✅ Лог приложения: $APP_LOG ($log_size)"
    else
        print_warning "⚠️  Лог приложения: Не найден"
    fi
    
    # Проверка доступности веб-интерфейса
    local server_ip=$(hostname -I | awk '{print $1}')
    if curl -k -s "https://$server_ip" >/dev/null 2>&1; then
        print_success "✅ Веб-интерфейс: Доступен"
    else
        print_warning "⚠️  Веб-интерфейс: Недоступен"
        all_ok=false
    fi
    
    print_separator
    
    if $all_ok; then
        print_success "🎉 Все компоненты работают корректно!"
    else
        print_warning "⚠️  Обнаружены проблемы. Проверьте логи."
    fi
    
    # Информация о доступе
    echo
    print_status "🌐 Доступ к веб-интерфейсу:"
    print_status "   HTTPS: https://$server_ip"
    print_status "   HTTP:  http://$server_ip (редирект на HTTPS)"
    echo
}

# Быстрая проверка статуса
check_status() {
    print_header "СТАТУС СИСТЕМЫ"
    
    # Проверка сервиса WireGuard Web
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "✓ $APP_NAME: Запущен"
    else
        print_error "✗ $APP_NAME: Остановлен"
        print_status "Для запуска: systemctl start $SERVICE_NAME"
    fi
    
    # Проверка Nginx
    if systemctl is-active --quiet nginx; then
        print_success "✓ Nginx: Запущен"
    else
        print_error "✗ Nginx: Остановлен"
        print_status "Для запуска: systemctl start nginx"
    fi
    
    # Проверка портов
    print_status "Проверка портов..."
    if netstat -tlnp 2>/dev/null | grep -q ":5000"; then
        print_success "✓ Flask приложение слушает порт 5000"
    else
        print_warning "⚠ Flask приложение НЕ слушает порт 5000"
        print_status "Это объясняет ошибку 'connect() failed (111)' в Nginx"
    fi
    
    if netstat -tlnp 2>/dev/null | grep -q ":443"; then
        print_success "✓ HTTPS порт 443 открыт"
    else
        print_warning "⚠ HTTPS порт 443 не открыт"
    fi
    
    # Проверка подключения к Flask приложению
    print_status "Тестирование подключения к Flask..."
    if curl -s --connect-timeout 3 http://127.0.0.1:5000 >/dev/null 2>&1; then
        print_success "✓ Flask приложение отвечает"
    else
        print_error "✗ Flask приложение НЕ отвечает на порту 5000"
        print_status "Проверьте логи: journalctl -u $SERVICE_NAME -f"
    fi
}

# Запуск приложения
start_app() {
    print_header "ЗАПУСК $APP_NAME"
    
    check_root "start"
    
    print_status "Запуск сервисов..."
    
    systemctl start "$SERVICE_NAME"
    systemctl start nginx
    
    sleep 2
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "$APP_NAME запущен"
    else
        print_error "Не удалось запустить $APP_NAME"
        print_status "Проверьте логи: journalctl -u $SERVICE_NAME -f"
        exit 1
    fi
    
    check_status
}

# Остановка приложения
stop_app() {
    print_header "ОСТАНОВКА $APP_NAME"
    
    check_root "stop"
    
    print_status "Остановка сервисов..."
    
    systemctl stop "$SERVICE_NAME"
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_error "Не удалось остановить $APP_NAME"
        exit 1
    else
        print_success "$APP_NAME остановлен"
    fi
    
    check_status
}

# Перезапуск приложения
restart_app() {
    print_header "ПЕРЕЗАПУСК $APP_NAME"
    
    check_root "restart"
    
    print_status "Обновление файлов приложения..."
    
    # Копируем обновленные файлы, если они есть в текущей директории
    if [[ -f "app.py" ]]; then
        print_status "Обновление app.py..."
        cp app.py "$INSTALL_DIR/"
        chown "$APP_USER:$APP_USER" "$INSTALL_DIR/app.py"
    fi
    
    print_status "Перезапуск сервисов..."
    
    systemctl restart "$SERVICE_NAME"
    systemctl reload nginx
    
    sleep 3
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "$APP_NAME перезапущен"
    else
        print_error "Не удалось перезапустить $APP_NAME"
        print_status "Проверьте логи: journalctl -u $SERVICE_NAME -f"
        exit 1
    fi
    
    check_status
}

# Просмотр логов
view_logs() {
    print_header "ЛОГИ $APP_NAME"
    
    echo -e "${CYAN}Выберите тип логов:${NC}"
    echo "1) Логи приложения (последние 50 строк)"
    echo "2) Логи приложения (в реальном времени)"
    echo "3) Системные логи сервиса (последние 50 строк)"
    echo "4) Системные логи сервиса (в реальном времени)"
    echo "5) Логи Nginx (доступ)"
    echo "6) Логи Nginx (ошибки)"
    echo "7) Все логи (краткий обзор)"
    echo
    
    read -p "Введите номер (1-7): " choice
    
    case $choice in
        1)
            if [[ -f "$APP_LOG" ]]; then
                print_status "Последние 50 строк лога приложения:"
                print_separator
                tail -n 50 "$APP_LOG"
            else
                print_warning "Лог приложения не найден: $APP_LOG"
            fi
            ;;
        2)
            if [[ -f "$APP_LOG" ]]; then
                print_status "Логи приложения в реальном времени (Ctrl+C для выхода):"
                print_separator
                tail -f "$APP_LOG"
            else
                print_warning "Лог приложения не найден: $APP_LOG"
            fi
            ;;
        3)
            print_status "Последние 50 строк системного лога:"
            print_separator
            journalctl -u "$SERVICE_NAME" -n 50 --no-pager
            ;;
        4)
            print_status "Системные логи в реальном времени (Ctrl+C для выхода):"
            print_separator
            journalctl -u "$SERVICE_NAME" -f
            ;;
        5)
            if [[ -f "/var/log/nginx/wireguard-web-access.log" ]]; then
                print_status "Последние 50 строк лога доступа Nginx:"
                print_separator
                tail -n 50 /var/log/nginx/wireguard-web-access.log
            else
                print_warning "Лог доступа Nginx не найден"
            fi
            ;;
        6)
            if [[ -f "/var/log/nginx/wireguard-web-error.log" ]]; then
                print_status "Последние 50 строк лога ошибок Nginx:"
                print_separator
                tail -n 50 /var/log/nginx/wireguard-web-error.log
            else
                print_warning "Лог ошибок Nginx не найден"
            fi
            ;;
        7)
            print_status "Обзор всех логов:"
            print_separator
            
            echo -e "${YELLOW}=== Системный лог сервиса (последние 10 строк) ===${NC}"
            journalctl -u "$SERVICE_NAME" -n 10 --no-pager
            echo
            
            if [[ -f "$APP_LOG" ]]; then
                echo -e "${YELLOW}=== Лог приложения (последние 10 строк) ===${NC}"
                tail -n 10 "$APP_LOG"
                echo
            fi
            
            if [[ -f "/var/log/nginx/wireguard-web-error.log" ]]; then
                echo -e "${YELLOW}=== Ошибки Nginx (последние 5 строк) ===${NC}"
                tail -n 5 /var/log/nginx/wireguard-web-error.log
                echo
            fi
            ;;
        *)
            print_error "Неверный выбор"
            exit 1
            ;;
    esac
}

# Удаление приложения
uninstall_app() {
    print_header "УДАЛЕНИЕ $APP_NAME"
    
    check_root "uninstall"
    
    print_warning "⚠️  Это действие удалит веб-интерфейс управления WireGuard"
    print_warning "⚠️  Сами клиенты WireGuard и их конфигурации НЕ будут удалены"
    echo
    read -p "Вы уверены, что хотите продолжить? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Отмена удаления"
        exit 0
    fi
    
    print_separator
    
    # Остановка и отключение сервиса
    print_status "Остановка сервиса $SERVICE_NAME..."
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    
    # Удаление systemd сервиса
    print_status "Удаление systemd сервиса..."
    rm -f "$SYSTEMD_SERVICE"
    systemctl daemon-reload
    
    # Удаление конфигурации Nginx
    print_status "Удаление конфигурации Nginx..."
    rm -f "$NGINX_CONFIG"
    rm -f /etc/nginx/sites-enabled/wireguard-web
    systemctl reload nginx 2>/dev/null || true
    
    # Удаление директории приложения
    if [[ -d "$INSTALL_DIR" ]]; then
        print_status "Удаление директории приложения: $INSTALL_DIR"
        rm -rf "$INSTALL_DIR"
    fi
    
    # Удаление логов
    if [[ -d "$LOG_DIR" ]]; then
        print_status "Удаление логов: $LOG_DIR"
        rm -rf "$LOG_DIR"
    fi
    
    # Удаление пользователя
    if id "$APP_USER" &>/dev/null; then
        print_status "Удаление пользователя $APP_USER..."
        userdel "$APP_USER" 2>/dev/null || true
    fi
    
    # Опциональное удаление конфигурации
    echo
    read -p "Удалить конфигурацию администратора? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Удаление конфигурации администратора..."
        rm -rf "$CONFIG_DIR"
        print_success "Конфигурация администратора удалена"
    else
        print_status "Конфигурация администратора сохранена в $CONFIG_DIR"
    fi
    
    print_separator
    print_success "🗑️  $APP_NAME успешно удален"
    print_status "🔒 WireGuard сервер и клиенты остались без изменений"
}

# Информация об установке
print_installation_info() {
    local server_ip=$(curl -s ifconfig.me || curl -s ipinfo.io/ip || hostname -I | awk '{print $1}')
    
    print_success "🎉 УСТАНОВКА ЗАВЕРШЕНА УСПЕШНО!"
    echo
    print_status "📋 Информация о доступе:"
    
    if [[ -n "$DOMAIN_NAME" ]]; then
        print_status "   🌐 HTTPS: https://$DOMAIN_NAME"
        if [[ "$USE_LETSENCRYPT" == "true" ]]; then
            print_success "   🔒 SSL: Let's Encrypt (доверенный сертификат)"
        else
            print_warning "   🔒 SSL: Самоподписанный сертификат"
        fi
    else
        print_status "   🌐 HTTPS: https://$server_ip"
        print_warning "   🔒 SSL: Самоподписанный сертификат (предупреждение в браузере)"
    fi
    
    print_status "   🌐 HTTP:  http://${DOMAIN_NAME:-$server_ip} (автоматический редирект на HTTPS)"
    echo
    print_status "🔐 Учетные данные для входа:"
    print_success "   👤 Логин: admin"
    print_success "   🔑 Пароль: admin123"
    echo
    print_warning "⚠️  ВАЖНО: Обязательно смените пароль после первого входа!"
    
    if [[ "$USE_LETSENCRYPT" == "true" ]]; then
        echo
        print_status "🔄 Автообновление SSL сертификата настроено"
    fi
    
    echo
    print_status "📁 Расположение файлов:"
    print_status "   📂 Приложение: $INSTALL_DIR"
    print_status "   📂 Конфигурация: $CONFIG_DIR"
    print_status "   📂 Логи: $LOG_DIR"
    echo
    print_status "🔧 Управление через меню:"
    print_status "   sudo $0"
    echo
}

# Локальный запуск приложения (dev-режим, аналог run_local.sh)
dev_run_local() {
    print_header "ЛОКАЛЬНЫЙ ЗАПУСК (DEV)"

    # Здесь НЕ требуем root — dev-режим
    PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "${PROJECT_DIR}"

    VENV_DIR="${PROJECT_DIR}/.venv"

    print_status "Каталог проекта: ${PROJECT_DIR}"

    if ! command -v python3 >/dev/null 2>&1; then
        print_error "Не найден исполняемый файл python3"
        print_status "Установите Python 3 (на macOS: 'brew install python', на Linux: через пакетный менеджер)."
        return 1
    fi

    if [[ ! -f "${PROJECT_DIR}/requirements.txt" ]]; then
        print_error "Не найден requirements.txt в корне проекта"
        return 1
    fi

    # Создание виртуального окружения при необходимости
    if [[ ! -d "${VENV_DIR}" ]]; then
        print_status "Создаю виртуальное окружение .venv ..."
        python3 -m venv "${VENV_DIR}"
    fi

    print_status "Активирую виртуальное окружение .venv"
    # shellcheck disable=SC1090
    source "${VENV_DIR}/bin/activate"

    print_status "Обновляю pip и устанавливаю зависимости из requirements.txt ..."
    pip install --upgrade pip
    pip install -r requirements.txt

    export FLASK_ENV=development
    export PYTHONPATH="${PROJECT_DIR}:${PYTHONPATH:-}"
    export PORT="${PORT:-5001}"

    print_status "Запуск app.py на порту ${PORT} (Ctrl+C для остановки)"

    if [[ -f "${PROJECT_DIR}/app.py" ]]; then
        python3 app.py
    else
        print_error "Не найден файл app.py в корне проекта"
        return 1
    fi
}

# Показать главное меню
show_main_menu() {
    clear
    print_header "WIREGUARD WEB MANAGER"
    
    echo -e "${CYAN}Выберите действие:${NC}"
    echo
    echo -e "  ${GREEN}1)${NC} Установить приложение"
    echo -e "  ${GREEN}2)${NC} Запустить приложение"
    echo -e "  ${GREEN}3)${NC} Остановить приложение"
    echo -e "  ${GREEN}4)${NC} Перезапустить приложение"
    echo -e "  ${GREEN}5)${NC} Проверить статус (краткий)"
    echo -e "  ${GREEN}6)${NC} Проверить статус (подробный)"
    echo -e "  ${GREEN}7)${NC} Просмотреть логи"
    echo -e "  ${GREEN}8)${NC} Удалить приложение"
    echo -e "  ${GREEN}9)${NC} Справка"
    echo -e "  ${GREEN}10)${NC} Добавить домен (отдельный конфиг + SSL)"
    echo -e "  ${GREEN}11)${NC} Локальный запуск (режим разработки)"
    echo -e "  ${GREEN}B)${NC} Управление заблокированными IP (rate limiting)"
    echo -e "  ${CYAN}I)${NC} Информация для доступа"
    echo -e "  ${YELLOW}D)${NC} Диагностика проблем"
    echo -e "  ${PURPLE}F)${NC} Исправить права доступа"
    echo -e "  ${RED}0)${NC} Выход"
    echo
    echo -e "${YELLOW}Статус сервисов:${NC}"
    
    # Быстрая проверка статуса
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        echo -e "  WireGuard Web: ${GREEN}●${NC} Запущен"
    else
        echo -e "  WireGuard Web: ${RED}●${NC} Остановлен"
    fi
    
    if systemctl is-active --quiet nginx 2>/dev/null; then
        echo -e "  Nginx: ${GREEN}●${NC} Запущен"
    else
        echo -e "  Nginx: ${RED}●${NC} Остановлен"
    fi
    
    echo
    print_separator
}

# --- Управление заблокированными IP (rate limiting) ---

show_blocked_ips() {
    print_status "Проверка заблокированных IP (rate limiting)..."
    echo

    python3 << EOF
import json
import os
from datetime import datetime

blocked_file = "${BLOCKED_IPS_FILE}"

try:
    if not os.path.exists(blocked_file):
        print("✅ Нет заблокированных IP адресов (файл не найден)")
        raise SystemExit(0)

    with open(blocked_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not data:
        print("✅ Нет заблокированных IP адресов")
        raise SystemExit(0)

    now = datetime.now().timestamp()
    active = []

    for ip, info in data.items():
        if not isinstance(info, dict):
            continue
        expires_at = info.get("expires_at", 0)
        if expires_at <= now:
            continue
        remaining = int(expires_at - now)
        active.append({
            "ip": ip,
            "blocked_at": datetime.fromtimestamp(info.get("blocked_at", now)).strftime("%Y-%m-%d %H:%M:%S"),
            "expires_at": datetime.fromtimestamp(expires_at).strftime("%Y-%m-%d %H:%M:%S"),
            "reason": info.get("reason", "Rate limit exceeded"),
            "attempts": info.get("attempts", 0),
            "remaining": remaining,
        })

    if not active:
        print("✅ Нет активных заблокированных IP адресов")
        raise SystemExit(0)

    print(f"🚫 Активных заблокированных IP: {len(active)}")
    print("=" * 80)
    for idx, item in enumerate(active, 1):
        print(f"{idx}. IP: {item['ip']}")
        print(f"   📅 Заблокирован: {item['blocked_at']}")
        print(f"   ⏰ Истечёт:     {item['expires_at']}")
        print(f"   🔍 Причина:    {item['reason']}")
        print(f"   🔢 Попыток:    {item['attempts']}")
        print(f"   ⏳ Осталось:   {item['remaining']} секунд")
        print("-" * 80)

except Exception as e:
    print(f"❌ Ошибка при чтении {blocked_file}: {e}")
EOF
}

unblock_single_ip() {
    local ip="$1"
    if [[ -z "$ip" ]]; then
        print_error "Не указан IP адрес для разблокировки"
        return 1
    fi

    print_status "Разблокировка IP: $ip"

    python3 << EOF
import json
import os

blocked_file = "${BLOCKED_IPS_FILE}"
ip = "${ip}"

try:
    if not os.path.exists(blocked_file):
        print(f"ℹ️  IP {ip} не был заблокирован (файл не найден)")
        raise SystemExit(0)

    with open(blocked_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    if ip not in data:
        print(f"ℹ️  IP {ip} не найден в списке блокировок")
        raise SystemExit(0)

    del data[ip]

    os.makedirs(os.path.dirname(blocked_file), exist_ok=True)
    with open(blocked_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"✅ IP {ip} успешно разблокирован")

except Exception as e:
    print(f"❌ Ошибка разблокировки: {e}")
EOF
}

unblock_all_ips_cli() {
    print_warning "Разблокируем все IP адреса из ${BLOCKED_IPS_FILE}..."

    python3 << EOF
import json
import os

blocked_file = "${BLOCKED_IPS_FILE}"

try:
    if not os.path.exists(blocked_file):
        print("ℹ️  Файл блокировок не найден, разблокировать нечего")
        raise SystemExit(0)

    with open(blocked_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    count = len(data)
    data.clear()

    os.makedirs(os.path.dirname(blocked_file), exist_ok=True)
    with open(blocked_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"🎉 Разблокировано IP адресов: {count}")

except Exception as e:
    print(f"❌ Ошибка при очистке блокировок: {e}")
EOF
}

emergency_unblock_all() {
    print_warning "🚨 ЭКСТРЕННАЯ разблокировка всех IP и очистка JSON‑файлов rate limiting"
    read -p "Введите 'YES' для подтверждения: " confirm
    if [[ "$confirm" != "YES" ]]; then
        print_status "Операция отменена"
        return 0
    fi

    unblock_all_ips_cli

    # Чистим вспомогательные JSON в директории логов
    if [[ -d "$LOG_DIR" ]]; then
        find "$LOG_DIR" -maxdepth 1 -type f -name "*rate*limit*.json" -o -name "blocked_ips.json" | while read -r f; do
            print_status "Очищаю файл: $f"
            python3 - << EOF
import json, os, sys
path = sys.argv[1]
try:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({}, fh)
except Exception:
    pass
EOF
        "$f"
        done
    fi

    print_success "Экстренная разблокировка завершена"
}

manage_blocked_menu() {
    while true; do
        clear
        print_header "УПРАВЛЕНИЕ ЗАБЛОКИРОВАННЫМИ IP (RATE LIMITING)"
        echo -e "${CYAN}Выберите действие:${NC}"
        echo
        echo -e "  ${GREEN}1)${NC} Показать заблокированные IP"
        echo -e "  ${GREEN}2)${NC} Разблокировать конкретный IP"
        echo -e "  ${GREEN}3)${NC} Разблокировать ВСЕ IP"
        echo -e "  ${RED}4)${NC} 🚨 ЭКСТРЕННАЯ разблокировка (очистить всё)"
        echo -e "  ${RED}0)${NC} Назад в главное меню"
        echo
        read -p "Введите номер действия: " choice
        echo

        case "$choice" in
            1)
                show_blocked_ips
                read -p "Нажмите Enter для продолжения..." ;;
            2)
                read -p "Введите IP для разблокировки: " ip
                [[ -n "$ip" ]] && unblock_single_ip "$ip" || print_error "IP не может быть пустым"
                read -p "Нажмите Enter для продолжения..." ;;
            3)
                read -p "Вы уверены, что хотите разблокировать ВСЕ IP? (yes/NO): " c
                if [[ "$c" =~ ^[Yy][Ee][Ss]$ ]]; then
                    unblock_all_ips_cli
                else
                    print_status "Операция отменена"
                fi
                read -p "Нажмите Enter для продолжения..." ;;
            4)
                emergency_unblock_all
                read -p "Нажмите Enter для продолжения..." ;;
            0)
                break ;;
            *)
                print_error "Неверный выбор"
                sleep 1 ;;
        esac
    done
}

# Диагностика проблем
diagnose_problems() {
    print_header "ДИАГНОСТИКА ПРОБЛЕМ"
    
    print_status "Проверка установки..."
    
    # Проверка файлов
    if [[ -f "$INSTALL_DIR/app.py" ]]; then
        print_success "✓ Файл приложения найден: $INSTALL_DIR/app.py"
    else
        print_error "✗ Файл приложения НЕ найден: $INSTALL_DIR/app.py"
    fi
    
    if [[ -f "$SYSTEMD_SERVICE" ]]; then
        print_success "✓ Systemd сервис найден: $SYSTEMD_SERVICE"
    else
        print_error "✗ Systemd сервис НЕ найден: $SYSTEMD_SERVICE"
    fi
    
    if [[ -f "$NGINX_CONFIG" ]]; then
        print_success "✓ Конфигурация Nginx найдена: $NGINX_CONFIG"
    else
        print_error "✗ Конфигурация Nginx НЕ найдена: $NGINX_CONFIG"
    fi
    
    # Проверка виртуального окружения
    if [[ -f "$VENV_PATH/bin/python" ]]; then
        print_success "✓ Виртуальное окружение Python найдено"
    else
        print_error "✗ Виртуальное окружение Python НЕ найдено"
    fi
    
    print_separator
    
    # Проверка статуса сервисов
    print_status "Статус сервисов:"
    systemctl status "$SERVICE_NAME" --no-pager -l
    echo
    systemctl status nginx --no-pager -l
    
    print_separator
    
    # Проверка логов
    print_status "Последние ошибки в логах Flask приложения:"
    if [[ -f "$ERROR_LOG" ]]; then
        tail -10 "$ERROR_LOG" 2>/dev/null || echo "Лог пуст или недоступен"
    else
        echo "Файл лога не найден: $ERROR_LOG"
    fi
    
    print_separator
    
    print_status "Последние ошибки systemd:"
    journalctl -u "$SERVICE_NAME" --no-pager -l -n 10
    
    print_separator
    
    # Проверка портов
    print_status "Открытые порты:"
    netstat -tlnp | grep -E ":(80|443|5000)" || echo "Порты 80, 443, 5000 не открыты"
    
    print_separator
    
    # Рекомендации
    print_status "Рекомендации по устранению проблем:"
    
    if ! systemctl is-active --quiet "$SERVICE_NAME"; then
        echo -e "  ${YELLOW}1.${NC} Запустите сервис: systemctl start $SERVICE_NAME"
        echo -e "  ${YELLOW}2.${NC} Проверьте логи: journalctl -u $SERVICE_NAME -f"
    fi
    
    if ! netstat -tlnp 2>/dev/null | grep -q ":5000"; then
        echo -e "  ${YELLOW}3.${NC} Flask приложение не слушает порт 5000"
        echo -e "     Проверьте конфигурацию в $INSTALL_DIR/app.py"
    fi
    
    echo -e "  ${YELLOW}4.${NC} Для просмотра логов в реальном времени:"
    echo -e "     journalctl -u $SERVICE_NAME -f"
    echo -e "  ${YELLOW}5.${NC} Для перезапуска всех сервисов:"
    echo -e "     systemctl restart $SERVICE_NAME nginx"
    
    echo
    read -p "Нажмите Enter для возврата в главное меню..."
}

# Показать информацию для доступа
show_access_info() {
    print_header "ИНФОРМАЦИЯ ДЛЯ ДОСТУПА"
    
    local server_ip=$(curl -s ifconfig.me || curl -s ipinfo.io/ip || hostname -I | awk '{print $1}')
    
    print_status "🌐 Веб-интерфейс доступен по адресу:"
    if [[ -f /etc/nginx/sites-enabled/wireguard-web ]] && grep -q "server_name.*\." /etc/nginx/sites-enabled/wireguard-web; then
        local domain=$(grep "server_name" /etc/nginx/sites-enabled/wireguard-web | head -1 | awk '{print $2}' | sed 's/;//')
        if [[ "$domain" != "_" ]]; then
            print_success "   🔗 https://$domain"
            DOMAIN_NAME="$domain"
        fi
    fi
    
    if [[ -z "$DOMAIN_NAME" || "$DOMAIN_NAME" == "_" ]]; then
        print_success "   🔗 https://$server_ip"
        print_warning "   ⚠️  Используется самоподписанный SSL сертификат"
        print_status "   📝 Браузер покажет предупреждение о безопасности - это нормально"
    fi
    
    print_separator
    
    print_status "🔐 Учетные данные для входа:"
    print_success "   👤 Логин: admin"
    print_success "   🔑 Пароль: admin123"
    
    print_separator
    
    print_status "📋 Статус сервисов:"
    if systemctl is-active --quiet wireguard-web; then
        print_success "   ✅ WireGuard Web: Запущен"
    else
        print_error "   ❌ WireGuard Web: Остановлен"
        print_status "      Для запуска: выберите пункт 2 в меню"
    fi
    
    if systemctl is-active --quiet nginx; then
        print_success "   ✅ Nginx: Запущен"
    else
        print_error "   ❌ Nginx: Остановлен"
        print_status "      Для запуска: sudo systemctl start nginx"
    fi
    
    print_separator
    
    print_warning "⚠️  ВАЖНЫЕ ЗАМЕЧАНИЯ:"
    echo -e "   • Обязательно смените пароль после первого входа"
    echo -e "   • Настройте файрвол для ограничения доступа"
    echo -e "   • Используйте сложные пароли для клиентов WireGuard"
    echo -e "   • Регулярно проверяйте логи на подозрительную активность"
    
    echo
    read -p "Нажмите Enter для возврата в главное меню..."
}

# Показать справку
show_help() {
    print_header "СПРАВКА ПО ИСПОЛЬЗОВАНИЮ"
    
    echo -e "${YELLOW}О программе:${NC}"
    echo -e "  WireGuard Web Manager - комплексный скрипт для управления"
    echo -e "  веб-интерфейсом WireGuard VPN сервера."
    echo
    echo -e "${YELLOW}Основные функции:${NC}"
    echo -e "  • Автоматическая установка и настройка"
    echo -e "  • Управление сервисами (запуск/остановка/перезапуск)"
    echo -e "  • Мониторинг состояния системы"
    echo -e "  • Просмотр логов в реальном времени"
    echo -e "  • Исправление прав доступа к WireGuard"
    echo -e "  • Диагностика проблем"
    echo -e "  • Безопасное удаление"
    echo
    echo -e "${YELLOW}Файлы и директории:${NC}"
    echo -e "  Приложение:    $INSTALL_DIR"
    echo -e "  Конфигурация:  $CONFIG_DIR"
    echo -e "  Логи:          $LOG_DIR"
    echo -e "  Сервис:        $SYSTEMD_SERVICE"
    echo
    echo -e "${YELLOW}Требования:${NC}"
    echo -e "  • Ubuntu/Debian, CentOS/RHEL/Rocky, или Fedora"
    echo -e "  • Python 3.6+"
    echo -e "  • Nginx"
    echo -e "  • Права root для установки и управления"
    echo
    echo -e "${YELLOW}Безопасность:${NC}"
    echo -e "  • SSL/TLS шифрование"
    echo -e "  • Ограничение скорости запросов"
    echo -e "  • Запуск от имени root для доступа к WireGuard"
    echo -e "  • Безопасные заголовки HTTP"
    echo -e "  • Автоматическое исправление прав доступа"
    echo
    read -p "Нажмите Enter для возврата в главное меню..."
}

# Обработка выбора пользователя
handle_menu_choice() {
    local choice="$1"
    
    case $choice in
        1)
            install_app
            ;;
        2)
            start_app
            ;;
        3)
            stop_app
            ;;
        4)
            restart_app
            ;;
        5)
            check_status
            echo
            read -p "Нажмите Enter для возврата в главное меню..."
            ;;
        6)
            check_status_detailed
            echo
            read -p "Нажмите Enter для возврата в главное меню..."
            ;;
        7)
            view_logs
            ;;
        8)
            uninstall_app
            ;;
        9)
            show_help
            ;;
        10)
            add_domain_for_existing_server
            echo
            read -p "Нажмите Enter для возврата в главное меню..."
            ;;
        11)
            dev_run_local
            ;;
        b|B)
            manage_blocked_menu
            ;;
        i|I)
            show_access_info
            ;;
        d|D)
            diagnose_problems
            ;;
        f|F)
            fix_permissions
            echo
            read -p "Нажмите Enter для возврата в главное меню..."
            ;;
        0)
            print_success "До свидания!"
            exit 0
            ;;
        *)
            print_error "Неверный выбор. Попробуйте еще раз."
            sleep 2
            ;;
    esac
}

# Основная логика
main() {
    # Если переданы аргументы командной строки, обрабатываем их (для обратной совместимости)
    if [[ $# -gt 0 ]]; then
        case "${1:-}" in
            install)
                install_app
                ;;
            start)
                start_app
                ;;
            stop)
                stop_app
                ;;
            restart)
                restart_app
                ;;
            status)
                check_status
                ;;
            status-full)
                check_status_detailed
                ;;
            logs)
                view_logs
                ;;
            blocked-list)
                show_blocked_ips
                ;;
            blocked-unblock)
                shift
                unblock_single_ip "${1:-}"
                ;;
            blocked-clear)
                unblock_all_ips_cli
                ;;
            blocked-emergency)
                emergency_unblock_all
                ;;
            uninstall)
                uninstall_app
                ;;
            fix-permissions)
                fix_permissions
                ;;
            diagnose)
                diagnose_problems
                read -p "Нажмите Enter для продолжения..."
                ;;
            dev-run-local)
                # Локальный запуск приложения из текущей директории (режим разработки)
                dev_run_local
                ;;
            help|--help|-h)
                show_help
                read -p "Нажмите Enter для продолжения..."
                ;;
            *)
                print_error "Неизвестная команда: $1"
                echo
                echo -e "${YELLOW}Доступные команды:${NC}"
                echo -e "  install       - Установить приложение"
                echo -e "  start         - Запустить приложение"
                echo -e "  stop          - Остановить приложение"
                echo -e "  restart       - Перезапустить приложение"
                echo -e "  status          - Проверить статус"
                echo -e "  status-full     - Подробный статус"
                echo -e "  logs            - Просмотреть логи"
                echo -e "  blocked-list    - Показать заблокированные IP"
                echo -e "  blocked-unblock - Разблокировать конкретный IP (wireguard-web-manager.sh blocked-unblock 1.2.3.4)"
                echo -e "  blocked-clear   - Разблокировать все IP"
                echo -e "  blocked-emergency - Экстренная разблокировка и очистка rate limiting JSON"
                echo -e "  dev-run-local     - Локальный запуск app.py в dev-режиме"
                echo -e "  fix-permissions   - Исправить права доступа"
                echo -e "  diagnose          - Диагностика проблем"
                echo -e "  uninstall         - Удалить приложение"
                echo -e "  help              - Показать справку"
                echo
                read -p "Нажмите Enter для продолжения..."
                ;;
        esac
        return
    fi
    
    # Интерактивное меню
    while true; do
        show_main_menu
        
        echo -n "Введите номер действия (0-11, B, I, D, F): "
        read -r choice
        
        echo
        handle_menu_choice "$choice"
        
        # Пауза после выполнения действия (кроме выхода и действий с собственной паузой)
        if [[ "$choice" != "0" ]] && [[ "$choice" != "5" ]] && [[ "$choice" != "6" ]] && [[ "$choice" != "9" ]] && [[ "$choice" != "f" ]] && [[ "$choice" != "F" ]] && [[ "$choice" != "d" ]] && [[ "$choice" != "D" ]] && [[ "$choice" != "i" ]] && [[ "$choice" != "I" ]]; then
            echo
            read -p "Нажмите Enter для возврата в главное меню..."
        fi
    done
}

# Запуск основной функции
main "$@"