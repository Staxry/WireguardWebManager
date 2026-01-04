#!/bin/bash

# Скрипт для сброса пароля администратора на стандартный
# Стандартный логин: admin
# Стандартный пароль: admin123

set +e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_status() {
    echo -e "${YELLOW}🔧 $1${NC}"
}

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║              СБРОС ПАРОЛЯ АДМИНИСТРАТОРА НА СТАНДАРТНЫЙ                     ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Возможные пути к файлу конфигурации
CONFIG_PATHS=(
    "/etc/wireguard/admin_config.json"
    "/etc/wireguard-web/admin_config.json"
    "/opt/wireguard-web/.admin_config.json"
    "$(pwd)/.admin_config.json"
    "$HOME/.admin_config.json"
)

# Стандартные значения
DEFAULT_USERNAME="admin"
DEFAULT_PASSWORD="admin123"
# Хеш пароля admin123 (из admin_config.py)
DEFAULT_PASSWORD_HASH="fixed_salt_2024:8e81e4bc00dd2a9627bffe393cd9e887d55b58661e27f37e6c5b4d81fb36c471"
DEFAULT_SECRET_KEY="wireguard-web-secret-key-2024"

# Ищем файл конфигурации
CONFIG_FILE=""
for path in "${CONFIG_PATHS[@]}"; do
    if [ -f "$path" ]; then
        CONFIG_FILE="$path"
        print_success "Найден файл конфигурации: $CONFIG_FILE"
        break
    fi
done

if [ -z "$CONFIG_FILE" ]; then
    print_error "Файл конфигурации не найден ни в одном из мест:"
    for path in "${CONFIG_PATHS[@]}"; do
        echo "   - $path"
    done
    echo ""
    print_status "Создаю новый файл конфигурации..."
    
    # Определяем, куда создать файл
    if [ -w "/etc/wireguard/" ]; then
        CONFIG_FILE="/etc/wireguard/admin_config.json"
        mkdir -p /etc/wireguard
    elif [ -w "/etc/wireguard-web/" ]; then
        CONFIG_FILE="/etc/wireguard-web/admin_config.json"
        mkdir -p /etc/wireguard-web
    else
        CONFIG_FILE="/opt/wireguard-web/.admin_config.json"
        mkdir -p /opt/wireguard-web
    fi
fi

# Создаем резервную копию
if [ -f "$CONFIG_FILE" ]; then
    BACKUP_FILE="${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    cp "$CONFIG_FILE" "$BACKUP_FILE"
    print_success "Создана резервная копия: $BACKUP_FILE"
fi

# Создаем новый конфиг со стандартными значениями
print_status "Создание конфигурации со стандартными значениями..."
cat > "$CONFIG_FILE" << EOF
{
  "username": "$DEFAULT_USERNAME",
  "password_hash": "$DEFAULT_PASSWORD_HASH",
  "secret_key": "$DEFAULT_SECRET_KEY",
  "session_timeout": 600,
  "max_login_attempts": 5,
  "lockout_duration": 300
}
EOF

# Устанавливаем правильные права
chmod 600 "$CONFIG_FILE"
chown root:root "$CONFIG_FILE" 2>/dev/null || true

print_success "Конфигурация создана/обновлена: $CONFIG_FILE"
echo ""
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                          ПАРОЛЬ СБРОШЕН                                      ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Стандартные учетные данные:"
echo "  Логин:    $DEFAULT_USERNAME"
echo "  Пароль:   $DEFAULT_PASSWORD"
echo ""
echo "Файл конфигурации: $CONFIG_FILE"
echo ""
print_status "Перезапустите сервис для применения изменений:"
echo "   sudo systemctl restart wireguard-web"
echo ""
