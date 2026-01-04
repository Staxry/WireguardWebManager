#!/usr/bin/env python3
"""
Скрипт для проверки зарегистрированных роутов Flask
"""

import sys
import os

# Добавляем путь к приложению
sys.path.insert(0, '/opt/wireguard-web')

try:
    from app import app
    
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║              ПРОВЕРКА ЗАРЕГИСТРИРОВАННЫХ РОУТОВ FLASK                        ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    print("")
    
    print("Все зарегистрированные роуты:")
    print("-" * 80)
    
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            'rule': rule.rule,
            'endpoint': rule.endpoint,
            'methods': sorted(rule.methods - {'OPTIONS', 'HEAD'}),
            'arguments': list(rule.arguments)
        })
    
    # Сортируем по правилу
    routes.sort(key=lambda x: x['rule'])
    
    for route in routes:
        methods_str = ', '.join(route['methods'])
        args_str = ', '.join(route['arguments']) if route['arguments'] else 'нет'
        print(f"  {route['rule']:50} -> {route['endpoint']:30} [{methods_str:20}] args: [{args_str}]")
    
    print("")
    print("-" * 80)
    print("")
    
    # Проверяем конкретно delete_client
    delete_routes = [r for r in routes if 'delete' in r['rule'].lower() or 'delete' in r['endpoint'].lower()]
    
    if delete_routes:
        print("Роуты, связанные с удалением:")
        for route in delete_routes:
            methods_str = ', '.join(route['methods'])
            print(f"  ✅ {route['rule']} -> {route['endpoint']} [{methods_str}]")
    else:
        print("❌ Роуты для удаления не найдены!")
    
    print("")
    
    # Тестируем сопоставление URL
    print("Тестирование сопоставления URL:")
    print("-" * 80)
    
    test_urls = [
        '/delete_client/123',
        '/delete_client/test',
        '/delete_client/123/',
    ]
    
    with app.test_request_context():
        for test_url in test_urls:
            try:
                rule, args = app.url_map.bind('').match(test_url, method='POST', return_rule=True)
                print(f"  ✅ {test_url:30} -> {rule.endpoint} {args}")
            except Exception as e:
                print(f"  ❌ {test_url:30} -> ОШИБКА: {e}")
    
    print("")
    
except Exception as e:
    print(f"❌ Ошибка при проверке роутов: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
