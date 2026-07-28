# VulnShop — учебный уязвимый сайт

Намеренно небезопасное веб-приложение для проекта **анализатора по информационной безопасности**.

> **Только локально.** Не деплоить в интернет и не использовать на реальных данных.

## Запуск

```bash
pip install -r requirements.txt
python app.py
```

Откройте: http://127.0.0.1:5000

Пересоздать БД (если нужно):

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

## Заложенные уязвимости

| Уязвимость | Где | Пример |
|------------|-----|--------|
| SQL Injection | `/login`, `/search` | `admin' --` или `' OR 1=1 --` |
| Reflected XSS | `/search?q=` | `<script>alert(1)</script>` |
| Stored XSS | `/product/1` (отзывы) | `<img src=x onerror=alert(1)>` |
| IDOR | `/profile?id=` | сменить id на чужой |
| Path Traversal | `/download?file=` | `../app.py` |
| Command Injection | `/ping` | `127.0.0.1 & whoami` |
| CSRF | `/transfer` | POST без CSRF-токена |
| Unrestricted Upload | `/upload` | любой файл |
| Broken Access Control | `/admin` | роль только из session |
| Information Disclosure | `/api/user/1` | пароли в JSON |
| Open Redirect | `/redirect?url=` | внешний URL |
| Hardcoded Secret | `app.secret_key` | в коде |
| Debug Mode | `app.run(debug=True)` | — |

## Структура

```
app.py              — сервер и уязвимая логика
templates/          — страницы
static/style.css    — стили
files/              — файлы для /download
uploads/            — загрузки пользователей
vulnshop.db         — SQLite (создаётся при старте)
```
