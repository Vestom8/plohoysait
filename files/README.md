# VulnShop — учебный уязвимый сайт

Намеренно небезопасное веб-приложение для проекта **анализатора по информационной безопасности**.
Имитирует интернет-магазин: каталог, корзина, заказы, профиль, обратная связь — и в каждом
разделе намеренно заложены одна или несколько уязвимостей.

> **Только локально.** Не деплоить в интернет и не использовать на реальных данных.
> `/fetch` (SSRF) и `/ping` (Command Injection) выполняют реальные действия в сети/ОС хоста.

## Запуск

```bash
pip install -r requirements.txt
python app.py
```

Откройте: http://127.0.0.1:5000

Пересоздать БД (если менялась схема или нужно сбросить данные):

```bash
python -c "from app import init_db; init_db()"
```

## Аккаунты

| Логин  | Пароль    | Роль  |
|--------|-----------|-------|
| admin  | admin123  | admin |
| alice  | password  | user  |
| bob    | qwerty    | user  |
| guest  | guest     | user  |

Регистрация новых аккаунтов открыта на `/register` (и сама по себе уязвима — см. ниже).

## Заложенные уязвимости

Полная машиночитаемая карта — **[`VULN_MAP.json`](../VULN_MAP.json)** в корне репозитория
(42 записи: id, CWE, OWASP Top 10, endpoint, параметр, severity, payload). Ниже — краткая сводка.

### Инъекции

| Уязвимость | Где | Пример |
|------------|-----|--------|
| SQL Injection (вход) | `/login` | `admin' --` |
| SQL Injection (поиск) | `/search?q=` | `%' OR 1=1 --` |
| Blind / Time-based SQLi | `/category/<cat>` | `electronics' OR SLEEP(2)='0` |
| Reflected XSS | `/search?q=`, `/category/<cat>` | `<script>alert(1)</script>` |
| Stored XSS | `/product/<id>` (отзывы) | `<img src=x onerror=alert(1)>` |
| DOM-based XSS | `/about#` | `#<img src=x onerror=alert(1)>` |
| Command Injection | `/ping` | `127.0.0.1 & whoami` |
| SSTI (Jinja2) | `/signature` | `{{ 7*7 }}`, `{{ config }}` |
| XXE | `/feedback` | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` |
| Insecure Deserialization (YAML) | `/import-config` | `!!python/object/apply:os.popen ["id"]` |
| Insecure Deserialization (pickle/cookie) | `/cart` (cookie `cart`) | подделанный base64(pickle) |

### Аутентификация и сессии

| Уязвимость | Где | Пример |
|------------|-----|--------|
| Брутфорс без ограничений | `/login` | серия запросов без задержки/lockout |
| User Enumeration | `/register` | повторный логин `admin` |
| Предсказуемый reset-токен | `/forgot-password` | `token = md5(username)` |
| JWT без проверки подписи | `/api/session` | `verify_signature=False`, можно подделать `role` |
| Небезопасные флаги cookie | глобально | нет `HttpOnly`/`Secure`/`SameSite` |
| Hardcoded Secret | `app.secret_key` / `JWT_SECRET` | в коде, один и тот же ключ |

### Логика и API

| Уязвимость | Где | Пример |
|------------|-----|--------|
| Mass Assignment | `/register` | скрытые поля `role`, `balance` |
| IDOR (профиль) | `/profile?id=` | смена `id` на чужой |
| IDOR (заказы) | `/order/<id>` | смена `id` на чужой заказ |
| Price/Parameter Tampering | `/cart` | своя цена товара в форме |
| Business Logic — отрицательная сумма | `/api/transfer` | `{"amount": -1000}` |
| Race Condition (TOCTOU) | `/transfer` | параллельные запросы на всю сумму баланса |
| CSRF | `/transfer` | POST без CSRF-токена |
| SSRF | `/fetch?url=` | `http://127.0.0.1:5000/api/user/1` |
| Permissive CORS | `/api/*` | `Access-Control-Allow-Origin: *` + credentials |
| Unrestricted Upload | `/upload` | любой файл |
| Broken Access Control | `/admin` | роль только из cookie/session |
| Information Disclosure | `/api/user/<id>` | пароли в JSON |
| Open Redirect | `/redirect?url=` | внешний URL |

### Конфигурация и инфраструктура

| Уязвимость | Где | Пример |
|------------|-----|--------|
| Path Traversal | `/download?file=` | `../app.py` |
| Directory Listing | `/download` (без `file`) | листинг `/share/` |
| Exposed `.env` | `/.env` | фейковые секреты |
| Exposed `.git/config` | `/.git/config` | токен в URL remote |
| Exposed backup | `/download?file=backup.zip` | дамп БД |
| Debug Mode | `app.run(debug=True)` | Werkzeug debugger |
| Verbose Errors | `/search`, `/login` | текст ошибки SQLite |

## Контрольные точки (негативные примеры)

Для проверки ложных срабатываний сканера — тот же функционал, но реализованный безопасно.
Сканер **не должен** помечать их как уязвимые:

| Контроль | Где | Защита |
|----------|-----|--------|
| Параметризованный поиск | `/safe/search` | placeholders + автоэкранирование Jinja2 |
| Безопасный вход | `/safe/login` | параметризованный запрос, единое сообщение об ошибке |
| Перевод с CSRF-токеном | `/safe/transfer` | токен в session, `hmac.compare_digest` |
| Загрузка с allowlist | `/safe/upload` | allowlist расширений, лимит 2 МБ, случайное имя файла |

## Структура

```
VULN_MAP.json       — машиночитаемая карта уязвимостей и контрольных точек
files/
  app.py            — сервер и уязвимая логика (запуск: python app.py)
  requirements.txt  — зависимости (Flask, PyJWT, PyYAML, lxml, requests)
  share/            — файлы для /download (включая backup.zip)
  uploads/          — загрузки пользователей
  vulnshop.db       — SQLite (создаётся при старте)
templates/          — страницы (магазин, формы уязвимостей, /safe/* контроли)
static/style.css    — стили
```

## Полезные страницы

- `/hints` — шпаргалка для демонстрации со всеми payload'ами
- `/` — каталог со списком всех точек входа
- `VULN_MAP.json` — эталон для автоматической сверки с отчётом сканера
