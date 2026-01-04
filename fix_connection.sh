#!/bin/bash

# Скрипт для автоматического исправления проблемы подключения nginx к Flask
# Проблема: nginx не может подключиться к Flask на порту 5000

# Не прерываем выполнение при ошибках для полной диагностики
set +e

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║          АВТОМАТИЧЕСКОЕ ИСПРАВЛЕНИЕ ПОДКЛЮЧЕНИЯ NGINX → FLASK              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Функции для вывода
print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_status() {
    echo -e "${YELLOW}🔧 $1${NC}"
}

# Пути
INSTALL_DIR="/opt/wireguard-web"
SERVICE_NAME="wireguard-web"
APP_PY="$INSTALL_DIR/app.py"

# Проверка 1: Существует ли приложение
print_status "Проверка 1: Существование приложения..."
if [ ! -f "$APP_PY" ]; then
    print_error "Файл $APP_PY не найден!"
    echo "Проверяю альтернативные пути..."
    
    # Проверяем текущую директорию
    if [ -f "./app.py" ]; then
        CURRENT_DIR=$(pwd)
        print_status "Найдено приложение в: $CURRENT_DIR"
        INSTALL_DIR="$CURRENT_DIR"
        APP_PY="$INSTALL_DIR/app.py"
    else
        print_error "Приложение не найдено ни в /opt/wireguard-web, ни в текущей директории"
        exit 1
    fi
else
    print_success "Приложение найдено: $APP_PY"
fi

# Проверка 2: Слушает ли что-то порт 5000
print_status "Проверка 2: Проверка порта 5000..."
PORT_CHECK=$(netstat -tlnp 2>/dev/null | grep ':5000' || ss -tlnp 2>/dev/null | grep ':5000' || echo "")
if [ -z "$PORT_CHECK" ]; then
    print_error "Порт 5000 не слушается!"
else
    print_success "Порт 5000 слушается:"
    echo "   $PORT_CHECK"
fi

# Проверка 3: Статус systemd сервиса
print_status "Проверка 3: Статус systemd сервиса..."
if systemctl is-active --quiet "$SERVICE_NAME"; then
    print_success "Сервис $SERVICE_NAME активен"
else
    print_error "Сервис $SERVICE_NAME не активен"
fi

# Проверка 4: Проверка конфигурации app.py (порт и хост)
print_status "Проверка 4: Конфигурация app.py..."
if [ ! -f "$APP_PY" ]; then
    print_error "Не могу проверить $APP_PY - файл не найден"
else
    # Проверяем, что app.run использует правильный хост и порт
    HOST_CHECK=$(grep -E "app\.run.*host" "$APP_PY" | grep -v "^#" || echo "")
    PORT_CHECK_CFG=$(grep -E "app\.run.*port|PORT.*=" "$APP_PY" | grep -v "^#" || echo "")
    
    if echo "$HOST_CHECK" | grep -q "0.0.0.0"; then
        print_success "Хост настроен правильно (0.0.0.0)"
    else
        print_error "Хост не настроен на 0.0.0.0 (должен быть доступен для nginx)"
        print_status "Исправляю хост в app.py..."
        
        # Создаем резервную копию
        cp "$APP_PY" "$APP_PY.backup.$(date +%Y%m%d_%H%M%S)"
        
        # Исправляем host на 0.0.0.0 если там что-то другое
        sed -i "s/app\.run(host='[^']*'/app.run(host='0.0.0.0'/g" "$APP_PY"
        sed -i 's/app\.run(host="[^"]*"/app.run(host="0.0.0.0"/g' "$APP_PY"
        
        print_success "Хост исправлен на 0.0.0.0"
    fi
    
    if echo "$PORT_CHECK_CFG" | grep -q "5000"; then
        print_success "Порт настроен правильно (5000)"
    else
        print_status "Проверяю настройку порта..."
        # Порт может быть через переменную окружения, это нормально
        if echo "$PORT_CHECK_CFG" | grep -q "PORT"; then
            print_success "Порт настраивается через переменную окружения"
        else
            print_error "Порт не найден в конфигурации"
        fi
    fi
fi

# Проверка 5: Логи сервиса и приложения на ошибки
print_status "Проверка 5: Анализ логов..."
# Проверяем логи приложения
APP_LOG="/var/log/wireguard-web/app.log"
ERROR_LOG="/var/log/wireguard-web/error.log"

if [ -f "$ERROR_LOG" ]; then
    print_status "Проверка логов ошибок приложения..."
    RECENT_APP_ERRORS=$(tail -20 "$ERROR_LOG" 2>/dev/null | grep -i "error\|exception\|traceback\|failed\|import" || echo "")
    if [ -n "$RECENT_APP_ERRORS" ]; then
        print_error "Найдены ошибки в логах приложения:"
        echo "$RECENT_APP_ERRORS" | head -10
    fi
fi

if [ -f "$APP_LOG" ]; then
    print_status "Проверка логов приложения..."
    RECENT_APP_OUTPUT=$(tail -20 "$APP_LOG" 2>/dev/null || echo "")
    if [ -n "$RECENT_APP_OUTPUT" ]; then
        print_success "Логи приложения найдены (последние строки):"
        echo "$RECENT_APP_OUTPUT" | tail -5
    fi
fi

# Проверяем системные логи
RECENT_ERRORS=$(journalctl -u "$SERVICE_NAME" -n 100 --no-pager 2>/dev/null | grep -i "error\|exception\|traceback\|failed" | tail -5 || echo "")
if [ -z "$RECENT_ERRORS" ]; then
    print_success "Критических ошибок в системных логах не найдено"
else
    print_error "Найдены ошибки в системных логах:"
    echo "$RECENT_ERRORS" | while IFS= read -r line; do
        echo "   $line"
    done
fi

# Проверка 6: Проверка systemd сервиса - правильный ли путь и логирование
print_status "Проверка 6: Конфигурация systemd сервиса..."
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
if [ -f "$SERVICE_FILE" ]; then
    SERVICE_WORKDIR=$(grep "^WorkingDirectory=" "$SERVICE_FILE" | cut -d'=' -f2 || echo "")
    SERVICE_EXEC=$(grep "^ExecStart=" "$SERVICE_FILE" | cut -d'=' -f2- || echo "")
    HAS_LOGGING=$(grep -E "StandardOutput|StandardError" "$SERVICE_FILE" || echo "")
    
    NEEDS_FIX=false
    
    if [ -n "$SERVICE_WORKDIR" ] && [ -d "$SERVICE_WORKDIR" ]; then
        print_success "WorkingDirectory существует: $SERVICE_WORKDIR"
    else
        print_error "WorkingDirectory в сервисе не существует: $SERVICE_WORKDIR"
        NEEDS_FIX=true
    fi
    
    if [ -z "$HAS_LOGGING" ]; then
        print_error "В сервисе отсутствует настройка логирования!"
        print_status "Без логирования невозможно увидеть ошибки приложения"
        NEEDS_FIX=true
    else
        print_success "Логирование настроено"
    fi
    
    # Проверяем строгие ограничения безопасности, которые могут блокировать доступ
    if grep -q "ProtectSystem=strict" "$SERVICE_FILE"; then
        print_error "ProtectSystem=strict может блокировать доступ к файлам!"
        NEEDS_FIX=true
    fi
    
    if [ "$NEEDS_FIX" = true ]; then
        print_status "Исправляю systemd сервис..."
        
        # Создаем резервную копию
        cp "$SERVICE_FILE" "$SERVICE_FILE.backup.$(date +%Y%m%d_%H%M%S)"
        
        # Создаем правильный сервис файл
        cat > "$SERVICE_FILE" << EOF
[Unit]
Description=WireGuard Web Management Interface
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
Environment=PYTHONUNBUFFERED=1
Environment=PORT=5000
Environment=FLASK_APP=app.py
Environment=FLASK_ENV=production
ExecStart=/usr/bin/python3 $APP_PY
Restart=always
RestartSec=5
TimeoutStopSec=10

# Логирование (важно для диагностики!)
StandardOutput=journal
StandardError=journal

# Права доступа для WireGuard
ReadWritePaths=$INSTALL_DIR /etc/wireguard /root /tmp /var/log/wireguard-web
NoNewPrivileges=false
PrivateTmp=false
ProtectSystem=false
ProtectHome=false

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        print_success "Systemd сервис обновлен с правильными настройками"
    fi
    
    if [ -n "$SERVICE_EXEC" ] && [ -f "$(echo "$SERVICE_EXEC" | awk '{print $1}')" ]; then
        print_success "ExecStart указывает на существующий файл"
    else
        print_error "ExecStart указывает на несуществующий файл: $SERVICE_EXEC"
    fi
else
    print_error "Файл сервиса не найден: $SERVICE_FILE"
fi

# Проверка 7: Может ли приложение запуститься вручную (тест)
print_status "Проверка 7: Тестовый запуск приложения..."
cd "$INSTALL_DIR"
# Пытаемся запустить приложение в фоне на 2 секунды для проверки
TEST_PID=$(timeout 3 python3 app.py > /tmp/wireguard-test.log 2>&1 & echo $!)
sleep 2
if ps -p $TEST_PID > /dev/null 2>&1; then
    print_success "Приложение может запуститься!"
    kill $TEST_PID 2>/dev/null || true
    TEST_OUTPUT=$(cat /tmp/wireguard-test.log 2>/dev/null | head -10 || echo "")
    if [ -n "$TEST_OUTPUT" ]; then
        print_status "Вывод тестового запуска:"
        echo "$TEST_OUTPUT"
    fi
else
    print_error "Приложение не может запуститься!"
    TEST_ERROR=$(cat /tmp/wireguard-test.log 2>/dev/null || echo "")
    if [ -n "$TEST_ERROR" ]; then
        print_error "Ошибки при тестовом запуске:"
        echo "$TEST_ERROR" | head -20
    fi
fi
rm -f /tmp/wireguard-test.log
cd - > /dev/null

# Исправление: Перезапуск сервиса
print_status "Исправление: Перезапуск сервиса..."
systemctl stop "$SERVICE_NAME" 2>/dev/null || true
sleep 2

# Проверяем, что порт освободился
if netstat -tlnp 2>/dev/null | grep -q ':5000' || ss -tlnp 2>/dev/null | grep -q ':5000'; then
    print_error "Порт 5000 все еще занят после остановки сервиса!"
    print_status "Принудительное освобождение порта..."
    PID=$(lsof -ti:5000 2>/dev/null || fuser 5000/tcp 2>/dev/null | awk '{print $1}' || echo "")
    if [ -n "$PID" ]; then
        kill -9 $PID 2>/dev/null || true
        sleep 1
    fi
fi

# Запускаем сервис
systemctl start "$SERVICE_NAME"
sleep 3

# Проверка результата
if systemctl is-active --quiet "$SERVICE_NAME"; then
    print_success "Сервис успешно запущен"
    sleep 2
    
    # Показываем последние логи для проверки
    print_status "Последние логи сервиса (для проверки):"
    journalctl -u "$SERVICE_NAME" -n 15 --no-pager | tail -10
else
    print_error "Сервис не запустился!"
    print_status "Последние логи:"
    journalctl -u "$SERVICE_NAME" -n 30 --no-pager
    print_status "Попробуйте запустить приложение вручную для диагностики:"
    echo "   cd $INSTALL_DIR"
    echo "   python3 app.py"
    exit 1
fi

# Финальная проверка: слушает ли порт 5000
print_status "Финальная проверка: порт 5000..."
sleep 2
FINAL_CHECK=$(netstat -tlnp 2>/dev/null | grep ':5000' || ss -tlnp 2>/dev/null | grep ':5000' || echo "")
if [ -n "$FINAL_CHECK" ]; then
    print_success "Порт 5000 успешно слушается!"
    echo "   $FINAL_CHECK"
    
    # Проверяем, что это правильный интерфейс (0.0.0.0 или 127.0.0.1)
    if echo "$FINAL_CHECK" | grep -q "0.0.0.0:5000\|127.0.0.1:5000"; then
        print_success "Приложение слушает на правильном интерфейсе"
    else
        print_error "Приложение слушает на неожиданном интерфейсе"
    fi
else
    print_error "Порт 5000 все еще не слушается!"
    print_status "Проверяю логи для диагностики..."
    journalctl -u "$SERVICE_NAME" -n 30 --no-pager
    exit 1
fi

# Проверка подключения nginx
print_status "Проверка: тестовое подключение к приложению..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5000/ 2>/dev/null || echo "000")
if echo "$HTTP_CODE" | grep -q "200\|302\|401\|404"; then
    print_success "Приложение отвечает на запросы! (HTTP $HTTP_CODE)"
else
    print_error "Приложение не отвечает на запросы (HTTP $HTTP_CODE)"
    print_status "Проверяю логи приложения..."
    journalctl -u "$SERVICE_NAME" -n 30 --no-pager | tail -20
    
    # Проверяем, может ли приложение импортироваться
    print_status "Проверка импорта приложения..."
    cd "$INSTALL_DIR"
    IMPORT_TEST=$(python3 -c "import sys; sys.path.insert(0, '.'); import app" 2>&1)
    if [ $? -eq 0 ]; then
        print_success "Приложение импортируется без ошибок"
    else
        print_error "Ошибки при импорте приложения:"
        echo "$IMPORT_TEST" | head -20
        
        # Проверяем зависимости
        print_status "Проверка зависимостей Python..."
        MISSING_DEPS=$(python3 -c "
import sys
missing = []
try:
    import flask
except ImportError:
    missing.append('flask')
try:
    import configparser
except ImportError:
    missing.append('configparser')
if missing:
    print('Отсутствуют: ' + ', '.join(missing))
" 2>&1)
        
        if [ -n "$MISSING_DEPS" ]; then
            print_error "Отсутствуют зависимости: $MISSING_DEPS"
            print_status "Установите зависимости: pip3 install -r $INSTALL_DIR/requirements.txt"
        fi
    fi
    cd - > /dev/null
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                          ИСПРАВЛЕНИЕ ЗАВЕРШЕНО                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Следующие шаги:"
echo "  1. Проверьте логи nginx: sudo tail -f /var/log/nginx/wireguard-web-wireguard-manager_site-error.log"
echo "  2. Попробуйте удалить клиента через веб-интерфейс"
echo "  3. Если проблема сохраняется, проверьте логи: sudo journalctl -u $SERVICE_NAME -f"
echo ""
