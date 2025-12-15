// Управление темой
function applyInitialTheme() {
    // Если пользователь уже выбирал тему — используем её.
    let savedTheme = localStorage.getItem('theme');

    if (!savedTheme) {
        // Иначе пробуем определить по системной настройке.
        if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            savedTheme = 'dark';
        } else {
            savedTheme = 'light';
        }
        localStorage.setItem('theme', savedTheme);
    }

    document.documentElement.setAttribute('data-theme', savedTheme);

    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
        themeToggle.textContent = savedTheme === 'dark' ? '☀️' : '🌙';
    }
}

function toggleTheme() {
    const html = document.documentElement;
    const themeToggle = document.getElementById('themeToggle');
    const currentTheme = html.getAttribute('data-theme') || 'light';

    if (currentTheme === 'light') {
        html.setAttribute('data-theme', 'dark');
        if (themeToggle) themeToggle.textContent = '☀️';
        localStorage.setItem('theme', 'dark');
    } else {
        html.setAttribute('data-theme', 'light');
        if (themeToggle) themeToggle.textContent = '🌙';
        localStorage.setItem('theme', 'light');
    }
}

// Таймер сессии (фронтовый, синхронизация с backend — отдельная задача)
let sessionTimeLeft = 600; // 10 минут по умолчанию
let sessionTimer = null;

function setSessionTimeoutFromMeta() {
    const meta = document.querySelector('meta[name="session-timeout-seconds"]');
    if (meta) {
        const value = parseInt(meta.content, 10);
        if (!isNaN(value) && value > 0) {
            sessionTimeLeft = value;
        }
    }
}

function updateSessionTimer() {
    const timerElement = document.getElementById('time-left');
    if (!timerElement) return;

    const minutes = Math.floor(sessionTimeLeft / 60);
    const seconds = sessionTimeLeft % 60;
    timerElement.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;

    if (sessionTimeLeft <= 0) {
        clearInterval(sessionTimer);
        showNotification('Сессия истекла. Перенаправление на страницу входа...', 'warning');
        setTimeout(() => {
            window.location.href = '/logout';
        }, 2000);
        return;
    }

    // Предупреждение за 2 минуты
    if (sessionTimeLeft === 120) {
        showNotification('Сессия истечет через 2 минуты', 'warning');
    }

    // Предупреждение за 30 секунд
    if (sessionTimeLeft === 30) {
        showNotification('Сессия истечет через 30 секунд', 'error');
    }

    sessionTimeLeft--;
}

function resetSessionTimer() {
    setSessionTimeoutFromMeta();
}

function startSessionTimer() {
    if (document.getElementById('session-timer')) {
        setSessionTimeoutFromMeta();
        sessionTimer = setInterval(updateSessionTimer, 1000);

        // Сброс таймера при активности пользователя
        ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'].forEach(event => {
            document.addEventListener(event, resetSessionTimer, true);
        });
    }
}

// Универсальные уведомления
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;

    document.body.appendChild(notification);

    setTimeout(() => notification.classList.add('show'), 100);

    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => {
            if (document.body.contains(notification)) {
                document.body.removeChild(notification);
            }
        }, 300);
    }, 5000);
}

// Инициализация при загрузке страницы
document.addEventListener('DOMContentLoaded', function () {
    applyInitialTheme();
    startSessionTimer();
});


