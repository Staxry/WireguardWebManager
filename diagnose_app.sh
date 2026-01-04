#!/bin/bash

# Диагностический скрипт для проверки работы Flask приложения

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
echo "║              ДИАГНОСТИКА FLASK ПРИЛОЖЕНИЯ                                   ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

INSTALL_DIR="/opt/wireguard-web"
SERVICE_NAME="wireguard-web"

# 1. Проверка процесса
print_status "1. Проверка процесса Python на порту 5000..."
PID=$(netstat -tlnp 2>/dev/null | grep ':5000' | awk '{print $7}' | cut -d'/' -f1 || ss -tlnp 2>/dev/null | grep ':5000' | grep -oP 'pid=\K[0-9]+' || echo "")
if [ -n "$PID" ]; then
    print_success "Процесс найден: PID=$PID"
    ps aux | grep "$PID" | grep -v grep
else
    print_error "Процесс не найден!"
fi

# 2. Проверка подключения к приложению
print_status "2. Тестовое подключение к приложению..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://127.0.0.1:5000/ 2>&1)
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "401" ]; then
    print_success "Приложение отвечает! HTTP код: $HTTP_CODE"
else
    print_error "Приложение не отвечает! HTTP код: $HTTP_CODE"
    print_status "Попытка получить ответ с таймаутом..."
    curl -v --max-time 5 http://127.0.0.1:5000/ 2>&1 | head -20
fi

# 3. Проверка логов приложения напрямую
print_status "3. Проверка логов приложения..."
if [ -f "/var/log/wireguard-web/app.log" ]; then
    print_success "Лог приложения найден. Последние 20 строк:"
    tail -20 /var/log/wireguard-web/app.log
else
    print_error "Лог приложения не найден: /var/log/wireguard-web/app.log"
fi

if [ -f "/var/log/wireguard-web/error.log" ]; then
    print_status "Лог ошибок найден. Последние 20 строк:"
    tail -20 /var/log/wireguard-web/error.log
else
    print_error "Лог ошибок не найден: /var/log/wireguard-web/error.log"
fi

# 4. Проверка логов systemd с выводом приложения
print_status "4. Проверка логов systemd (с выводом приложения)..."
RECENT_LOGS=$(journalctl -u "$SERVICE_NAME" -n 100 --no-pager 2>/dev/null | grep -v "systemd\[1\]" | tail -30)
if [ -n "$RECENT_LOGS" ]; then
    print_success "Найдены логи приложения в systemd:"
    echo "$RECENT_LOGS"
else
    print_error "Логи приложения в systemd не найдены (только сообщения systemd)"
    print_status "Это означает, что приложение не выводит ничего в stdout/stderr"
fi

# 5. Проверка конфигурации systemd сервиса
print_status "5. Проверка конфигурации systemd сервиса..."
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
if [ -f "$SERVICE_FILE" ]; then
    echo "Содержимое сервиса:"
    cat "$SERVICE_FILE"
    
    # Проверяем логирование
    if grep -q "StandardOutput=journal" "$SERVICE_FILE" || grep -q "StandardError=journal" "$SERVICE_FILE"; then
        print_success "Логирование настроено в systemd"
    else
        print_error "Логирование НЕ настроено в systemd!"
        print_status "Приложение может работать, но его вывод не виден"
    fi
else
    print_error "Файл сервиса не найден: $SERVICE_FILE"
fi

# 6. Попытка запустить приложение вручную для проверки
print_status "6. Тестовый запуск приложения вручную (5 секунд)..."
cd "$INSTALL_DIR" 2>/dev/null || cd ~/WireguardWebManager

# Останавливаем сервис временно
systemctl stop "$SERVICE_NAME" 2>/dev/null
sleep 1

# Запускаем вручную с выводом
print_status "Запуск приложения вручную..."
timeout 5 python3 app.py > /tmp/app_manual_test.log 2>&1 &
MANUAL_PID=$!
sleep 3

if ps -p $MANUAL_PID > /dev/null 2>&1; then
    print_success "Приложение запустилось вручную!"
    print_status "Вывод приложения:"
    cat /tmp/app_manual_test.log
    kill $MANUAL_PID 2>/dev/null
else
    print_error "Приложение не запустилось вручную!"
    print_status "Вывод/ошибки:"
    cat /tmp/app_manual_test.log
fi

# Запускаем сервис обратно
systemctl start "$SERVICE_NAME" 2>/dev/null
sleep 2

# 7. Проверка после перезапуска
print_status "7. Финальная проверка после перезапуска..."
sleep 2
FINAL_CHECK=$(netstat -tlnp 2>/dev/null | grep ':5000' || ss -tlnp 2>/dev/null | grep ':5000' || echo "")
if [ -n "$FINAL_CHECK" ]; then
    print_success "Порт 5000 слушается:"
    echo "   $FINAL_CHECK"
    
    # Проверяем ответ
    FINAL_HTTP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 http://127.0.0.1:5000/ 2>&1)
    if [ "$FINAL_HTTP" = "200" ] || [ "$FINAL_HTTP" = "302" ] || [ "$FINAL_HTTP" = "401" ]; then
        print_success "Приложение отвечает на запросы! (HTTP $FINAL_HTTP)"
    else
        print_error "Приложение не отвечает! (HTTP $FINAL_HTTP)"
    fi
else
    print_error "Порт 5000 не слушается!"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                          ДИАГНОСТИКА ЗАВЕРШЕНА                               ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Если приложение не отвечает, проверьте:"
echo "  1. Логи: sudo journalctl -u $SERVICE_NAME -f"
echo "  2. Запуск вручную: cd $INSTALL_DIR && python3 app.py"
echo "  3. Зависимости: pip3 install -r $INSTALL_DIR/requirements.txt"
echo ""
