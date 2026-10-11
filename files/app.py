"""
VulnShop — намеренно уязвимое веб-приложение для анализатора ИБ.
ТОЛЬКО для локального тестирования. Не выставлять в интернет.

Полная карта уязвимостей и контрольных точек — см. VULN_MAP.json в корне репозитория.
"""

import base64
import hashlib
import hmac
import json
import os
import pickle
import secrets
import sqlite3
import subprocess
import time
import zipfile
from functools import wraps

import jwt
import requests
import yaml
from flask import (
    Flask,
    g,
    redirect,
    render_template,
    render_template_string,
    request,
    send_file,
    session,
    url_for,
)
from lxml import etree

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)

app = Flask(
    __name__,
    template_folder=os.path.join(ROOT_DIR, "templates"),
    static_folder=os.path.join(ROOT_DIR, "static"),
)
app.secret_key = "super-secret-key-12345"  # CWE-798: Hardcoded credentials
JWT_SECRET = app.secret_key  # CWE-798/CWE-522: переиспользование того же секрета для подписи JWT

# CWE-1004 / CWE-614: сессионная cookie без HttpOnly/Secure/SameSite
app.config.update(
    SESSION_COOKIE_HTTPONLY=False,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE=None,
)

DATABASE = os.path.join(BASE_DIR, "vulnshop.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
FILES_FOLDER = os.path.join(BASE_DIR, "share")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(FILES_FOLDER, exist_ok=True)

ALLOWED_UPLOAD_EXT = {"png", "jpg", "jpeg", "gif", "pdf", "txt"}
MAX_SAFE_UPLOAD_SIZE = 2 * 1024 * 1024


def _sqlite_sleep(seconds):
    """Пользовательская SQL-функция SLEEP(n) — включает time-based blind SQLi."""
    try:
        time.sleep(min(float(seconds), 8))
    except (TypeError, ValueError):
        pass
    return 0


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.create_function("SLEEP", 1, _sqlite_sleep)
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;
        DROP TABLE IF EXISTS comments;
        DROP TABLE IF EXISTS messages;
        DROP TABLE IF EXISTS orders;
        DROP TABLE IF EXISTS contact_messages;

        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            balance REAL DEFAULT 0
        );

        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            category TEXT
        );

        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            author TEXT,
            content TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            subject TEXT,
            body TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            items_json TEXT,
            total REAL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE contact_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT,
            message TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        INSERT INTO users (username, password, email, role, balance) VALUES
            ('admin', 'admin123', 'admin@vulnshop.local', 'admin', 9999.99),
            ('alice', 'password', 'alice@mail.test', 'user', 150.00),
            ('bob', 'qwerty', 'bob@mail.test', 'user', 75.50),
            ('guest', 'guest', 'guest@mail.test', 'user', 0);

        INSERT INTO products (name, description, price, category) VALUES
            ('Ноутбук ProBook', 'Мощный ноутбук для работы', 89990, 'electronics'),
            ('Смартфон XPhone', 'Флагманский смартфон', 64990, 'electronics'),
            ('Наушники SoundMax', 'Беспроводные наушники', 8990, 'audio'),
            ('Клавиатура MechKey', 'Механическая клавиатура', 5490, 'peripherals'),
            ('Мышь Precision', 'Игровая мышь', 2990, 'peripherals'),
            ('Монитор ViewClear 27"', 'IPS-монитор 27 дюймов, 144 Гц', 24990, 'electronics'),
            ('Колонка BassPod', 'Портативная Bluetooth-колонка', 4490, 'audio'),
            ('Рюкзак CarryAll', 'Рюкзак для ноутбука 15.6"', 3290, 'accessories');

        INSERT INTO comments (product_id, author, content) VALUES
            (1, 'alice', 'Отличный ноутбук, рекомендую!'),
            (1, 'bob', 'Дорого, но качество супер.');

        INSERT INTO messages (user_id, subject, body) VALUES
            (1, 'Секретный отчёт', 'Пароль от БД: root:P@ssw0rd!'),
            (2, 'Заказ #1024', 'Ваш заказ отправлен.'),
            (3, 'Промокод', 'Используйте SAVE20 для скидки.');
        """
    )
    db.commit()
    db.close()

    sample = os.path.join(FILES_FOLDER, "catalog.txt")
    if not os.path.exists(sample):
        with open(sample, "w", encoding="utf-8") as f:
            f.write("Каталог товаров VulnShop\n1. Ноутбук ProBook\n2. Смартфон XPhone\n")

    # CWE-530 / CWE-200: «забытый» бэкап с дампом БД, доступный через /download?file=backup.zip
    backup_path = os.path.join(FILES_FOLDER, "backup.zip")
    if not os.path.exists(backup_path):
        with zipfile.ZipFile(backup_path, "w") as zf:
            zf.writestr(
                "dump.sql",
                "-- VulnShop DB backup (автоматический, забыли удалить)\n"
                "INSERT INTO users (username, password, email, role) VALUES "
                "('admin', 'admin123', 'admin@vulnshop.local', 'admin');\n"
                "-- DB_ROOT_PASSWORD=root:P@ssw0rd!\n",
            )


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated


# ─── Корзина в cookie (небезопасная десериализация) ──────────────────────────


def _cart_from_cookie():
    raw = request.cookies.get("cart")
    if not raw:
        return []
    try:
        # CWE-502: Insecure Deserialization — pickle из cookie, подпись/HMAC отсутствуют
        return pickle.loads(base64.b64decode(raw))
    except Exception:
        return []


def _cart_to_cookie(cart_items):
    return base64.b64encode(pickle.dumps(cart_items)).decode()


# ─── Pages ───────────────────────────────────────────────────────────────────


@app.route("/")
def index():
    db = get_db()
    products = db.execute("SELECT * FROM products").fetchall()
    return render_template("index.html", products=products)


@app.route("/robots.txt")
def robots_txt():
    # CWE-200: robots.txt сам подсказывает «интересные» пути
    content = (
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /.env\n"
        "Disallow: /.git/\n"
        "Disallow: /backup.zip\n"
        "Disallow: /uploads/\n"
        "Disallow: /share/\n"
    )
    return app.response_class(content, mimetype="text/plain")


@app.route("/.env")
def dotenv_leak():
    # CWE-200 / CWE-540: доступный конфиг с «секретами» прямо из корня сайта
    content = (
        "APP_SECRET=super-secret-key-12345\n"
        "DB_PASSWORD=P@ssw0rd!\n"
        "AWS_ACCESS_KEY_ID=AKIAFAKEEXAMPLE1234\n"
        "AWS_SECRET_ACCESS_KEY=FAKE/exampleSecretKeyNotReal1234567890\n"
        "STRIPE_SECRET_KEY=sk_live_FAKE00000000000000000000\n"
        "SMTP_PASSWORD=letmein123\n"
    )
    return app.response_class(content, mimetype="text/plain")


@app.route("/.git/config")
def git_config_leak():
    # CWE-200 / CWE-540: «забытая» папка .git с токеном в URL remote
    content = (
        "[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n"
        '[remote "origin"]\n'
        "\turl = https://ci-bot:glpat-FAKEEXAMPLETOKEN0000@git.vulnshop.local/vulnshop.git\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        "[user]\n\temail = ci@vulnshop.local\n"
    )
    return app.response_class(content, mimetype="text/plain")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # CWE-89: SQL Injection — конкатенация без параметризации
        query = (
            f"SELECT * FROM users WHERE username = '{username}' "
            f"AND password = '{password}'"
        )
        try:
            db = get_db()
            user = db.execute(query).fetchone()
            if user:
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                resp = redirect(url_for("index"))
                # CWE-347: "remember me" токен подписан, но позже проверяется без сверки подписи
                token = jwt.encode(
                    {"username": user["username"], "role": user["role"]},
                    JWT_SECRET,
                    algorithm="HS256",
                )
                resp.set_cookie("remember_token", token)
                return resp
            # CWE-307: нет блокировки/замедления после неудачных попыток — брутфорс не ограничен
            error = "Неверный логин или пароль"
        except sqlite3.Error as e:
            # CWE-209: подробности ошибки БД показываются пользователю
            error = f"Ошибка БД: {e}"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    resp = redirect(url_for("index"))
    resp.delete_cookie("remember_token")
    return resp


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        # CWE-915: Mass Assignment — role/balance приходят прямо из формы (скрытые поля,
        # которые легко подменить в devtools/Burp) и пишутся в БД без проверки прав
        role = request.form.get("role", "user")
        balance = request.form.get("balance", "0") or "0"

        db = get_db()
        existing = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if existing:
            # CWE-204: User Enumeration — явное сообщение "уже занят" отличается от прочих ошибок
            error = f"Логин «{username}» уже занят"
        elif not username or not password:
            error = "Заполните логин и пароль"
        else:
            # CWE-521: отсутствует проверка сложности пароля — подойдёт и "1"
            try:
                db.execute(
                    "INSERT INTO users (username, password, email, role, balance) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (username, password, email, role, float(balance)),
                )
                db.commit()
            except (sqlite3.Error, ValueError) as e:
                error = f"Ошибка регистрации: {e}"
            else:
                user = db.execute(
                    "SELECT * FROM users WHERE username = ?", (username,)
                ).fetchone()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                return redirect(url_for("index"))
    return render_template("register.html", error=error)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    message = None
    if request.method == "POST":
        action = request.form.get("action", "request")
        username = request.form.get("username", "")
        if action == "request":
            # CWE-640 / CWE-330: предсказуемый токен восстановления —
            # md5(username) без соли, секрета и срока действия
            token = hashlib.md5(username.encode("utf-8")).hexdigest()
            message = (
                f"Токен восстановления для «{username}» "
                f"(в реальной системе отправляется на email, не показывается на странице): {token}"
            )
        elif action == "reset":
            supplied = request.form.get("token", "")
            new_password = request.form.get("new_password", "")
            expected = hashlib.md5(username.encode("utf-8")).hexdigest()
            if supplied == expected and new_password:
                db = get_db()
                db.execute(
                    "UPDATE users SET password = ? WHERE username = ?",
                    (new_password, username),
                )
                db.commit()
                message = "Пароль обновлён, можно входить с новым паролем."
            else:
                message = "Неверный токен или пустой пароль."
    return render_template("forgot_password.html", message=message)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # CWE-89: SQL Injection в поиске
    query = f"SELECT * FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'"
    products = []
    error = None
    try:
        db = get_db()
        products = db.execute(query).fetchall()
    except sqlite3.Error as e:
        error = str(e)
    # CWE-79: Reflected XSS — q отдаётся в шаблон без экранирования (см. search.html)
    return render_template("search.html", products=products, q=q, error=error)


@app.route("/category/<cat>")
def category(cat):
    # CWE-89: Blind / Time-based SQL Injection — ошибки скрыты, но есть SLEEP() для time-based
    # payload: electronics' OR SLEEP(3)='0  (видна задержка ответа без видимой ошибки)
    query = f"SELECT * FROM products WHERE category = '{cat}'"
    db = get_db()
    try:
        products = db.execute(query).fetchall()
    except sqlite3.Error:
        products = []
    # CWE-79: имя категории также отражается без экранирования
    return render_template("search.html", products=products, q=cat, error=None, category_mode=True)


@app.route("/product/<int:product_id>", methods=["GET", "POST"])
def product(product_id):
    db = get_db()
    prod = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    if not prod:
        return "Товар не найден", 404

    if request.method == "POST":
        author = request.form.get("author", session.get("username", "anonymous"))
        content = request.form.get("content", "")
        # CWE-79: Stored XSS — комментарии сохраняются как есть
        db.execute(
            "INSERT INTO comments (product_id, author, content) VALUES (?, ?, ?)",
            (product_id, author, content),
        )
        db.commit()
        return redirect(url_for("product", product_id=product_id))

    comments = db.execute(
        "SELECT * FROM comments WHERE product_id = ? ORDER BY id DESC",
        (product_id,),
    ).fetchall()
    return render_template("product.html", product=prod, comments=comments)


@app.route("/cart", methods=["GET", "POST"])
def cart():
    items = _cart_from_cookie()
    if request.method == "POST":
        product_id = request.form.get("product_id")
        # CWE-840: Business Logic — сервер доверяет цене/количеству из формы,
        # а не берёт цену из БД → "скидка" любого размера через devtools
        price = request.form.get("price")
        qty = request.form.get("qty", "1")
        db = get_db()
        prod = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
        if prod:
            try:
                items.append(
                    {
                        "id": prod["id"],
                        "name": prod["name"],
                        "price": float(price) if price not in (None, "") else prod["price"],
                        "qty": int(qty) if qty else 1,
                    }
                )
            except ValueError:
                pass
        resp = redirect(url_for("cart"))
        resp.set_cookie("cart", _cart_to_cookie(items))
        return resp
    total = sum(i["price"] * i["qty"] for i in items)
    return render_template("cart.html", items=items, total=total)


@app.route("/cart/clear")
def cart_clear():
    resp = redirect(url_for("cart"))
    resp.delete_cookie("cart")
    return resp


@app.route("/checkout", methods=["POST"])
@login_required
def checkout():
    items = _cart_from_cookie()
    total = sum(i["price"] * i["qty"] for i in items)
    db = get_db()
    db.execute(
        "INSERT INTO orders (user_id, items_json, total) VALUES (?, ?, ?)",
        (session["user_id"], json.dumps(items), total),
    )
    db.commit()
    resp = redirect(url_for("orders"))
    resp.set_cookie("cart", _cart_to_cookie([]))
    return resp


@app.route("/orders")
@login_required
def orders():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC", (session["user_id"],)
    ).fetchall()
    return render_template("orders.html", orders=rows)


@app.route("/order/<int:order_id>")
@login_required
def order_detail(order_id):
    db = get_db()
    # CWE-639: IDOR — заказ открывается по id без проверки user_id == session["user_id"]
    row = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if not row:
        return "Заказ не найден", 404
    items = json.loads(row["items_json"] or "[]")
    return render_template("orders.html", orders=[row], detail=row, items=items)


@app.route("/signature", methods=["GET", "POST"])
@login_required
def signature():
    rendered = None
    template_src = ""
    if request.method == "POST":
        template_src = request.form.get("template", "")
        try:
            # CWE-1336: Server-Side Template Injection — пользовательский текст
            # рендерится как Jinja2-шаблон на сервере
            rendered = render_template_string(template_src, user=session.get("username", ""))
        except Exception as e:
            rendered = f"Ошибка шаблона: {e}"
    return render_template("signature.html", rendered=rendered, template_src=template_src)


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    result = None
    error = None
    if request.method == "POST":
        xml_data = request.form.get("xml", "")
        f = request.files.get("xml_file")
        if f and f.filename:
            xml_data = f.read().decode("utf-8", errors="replace")
        if xml_data:
            try:
                # CWE-611: XXE — внешние и параметризованные сущности явно разрешены
                parser = etree.XMLParser(resolve_entities=True, no_network=False, dtd_validation=False)
                tree = etree.fromstring(xml_data.encode("utf-8"), parser=parser)
                name = tree.findtext("name") or ""
                msg_text = tree.findtext("message") or ""
                result = f"Спасибо, {name}! Сообщение получено: {msg_text}"
            except Exception as e:
                error = str(e)
    return render_template("feedback.html", result=result, error=error)


@app.route("/import-config", methods=["GET", "POST"])
@login_required
def import_config():
    result = None
    error = None
    if request.method == "POST":
        data = request.form.get("yaml", "")
        try:
            # CWE-502: Insecure Deserialization — полный yaml.Loader вместо safe_load
            parsed = yaml.load(data, Loader=yaml.Loader)
            result = repr(parsed)
        except Exception as e:
            error = str(e)
    return render_template("import_config.html", result=result, error=error)


@app.route("/fetch", methods=["GET", "POST"])
def fetch_url():
    result = None
    error = None
    if request.method == "POST":
        url = request.form.get("url", "")
        try:
            # CWE-918: SSRF — сервер реально ходит по переданному адресу,
            # включая localhost / внутренние сети, без allowlist и без фильтра схем
            resp = requests.get(url, timeout=5, allow_redirects=True)
            result = {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:2000],
            }
        except Exception as e:
            error = str(e)
    return render_template("fetch.html", result=result, error=error)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    message = None
    if request.method == "POST":
        name = request.form.get("name", "")
        email = request.form.get("email", "")
        text = request.form.get("message", "")
        db = get_db()
        db.execute(
            "INSERT INTO contact_messages (name, email, message) VALUES (?, ?, ?)",
            (name, email, text),
        )
        db.commit()
        message = "Спасибо! Сообщение отправлено."
    return render_template("contact.html", message=message)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/profile")
@login_required
def profile():
    # CWE-639: IDOR — user_id из query без проверки владельца
    user_id = request.args.get("id", session["user_id"])
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return "Пользователь не найден", 404
    messages = db.execute(
        "SELECT * FROM messages WHERE user_id = ?", (user_id,)
    ).fetchall()
    return render_template("profile.html", user=user, messages=messages)


@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    # CWE-352: CSRF — нет CSRF-токена
    # CWE-285: слабая авторизация — любой залогиненный может переводить
    message = None
    if request.method == "POST":
        to_user = request.form.get("to_user", "")
        amount = float(request.form.get("amount", 0))
        db = get_db()
        target = db.execute(
            "SELECT * FROM users WHERE username = ?", (to_user,)
        ).fetchone()
        sender = db.execute(
            "SELECT * FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        if target and amount > 0:
            # CWE-362: Race Condition (TOCTOU) — проверка баланса и его списание
            # разнесены по времени без блокировки/транзакции с изоляцией.
            # Параллельные запросы с amount == balance могут увести баланс в минус.
            if sender["balance"] >= amount:
                time.sleep(0.15)  # имитация обработки платежа — окно гонки
                db.execute(
                    "UPDATE users SET balance = balance - ? WHERE id = ?",
                    (amount, session["user_id"]),
                )
                db.execute(
                    "UPDATE users SET balance = balance + ? WHERE id = ?",
                    (amount, target["id"]),
                )
                db.commit()
                message = f"Переведено {amount} ₽ пользователю {to_user}"
            else:
                message = "Недостаточно средств"
        else:
            message = "Ошибка перевода"
    return render_template("transfer.html", message=message)


@app.route("/api/transfer", methods=["POST"])
@login_required
def api_transfer():
    data = request.get_json(silent=True) or {}
    to_user = data.get("to_user", "")
    try:
        amount = float(data.get("amount", 0))
    except (TypeError, ValueError):
        return {"error": "bad amount"}, 400
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE username = ?", (to_user,)).fetchone()
    if not target:
        return {"error": "user not found"}, 404
    # CWE-841: Business Logic — нет проверки amount > 0: отрицательная сумма
    # фактически переводит деньги СЕБЕ за счёт "получателя"
    db.execute(
        "UPDATE users SET balance = balance - ? WHERE id = ?", (amount, session["user_id"])
    )
    db.execute(
        "UPDATE users SET balance = balance + ? WHERE id = ?", (amount, target["id"])
    )
    db.commit()
    return {"ok": True, "to_user": to_user, "amount": amount}


@app.route("/api/session")
def api_session():
    token = request.cookies.get("remember_token") or request.headers.get(
        "Authorization", ""
    ).replace("Bearer ", "")
    if not token:
        return {"error": "no token"}, 401
    try:
        # CWE-347: Improper Verification of Cryptographic Signature —
        # verify_signature отключена, claims (включая role) принимаются как есть.
        # Позволяет подделать токен с alg=none и произвольным role=admin.
        payload = jwt.decode(
            token,
            options={"verify_signature": False},
            algorithms=["none", "HS256"],
        )
        return {"username": payload.get("username"), "role": payload.get("role")}
    except Exception as e:
        return {"error": str(e)}, 400


@app.route("/download")
def download():
    filename = request.args.get("file")
    if not filename:
        # CWE-548: Exposure Through Directory Listing — без имени файла отдаём список каталога
        entries = sorted(os.listdir(FILES_FOLDER))
        items = "".join(
            f'<li><a href="/download?file={e}">{e}</a></li>' for e in entries
        )
        return f"<h1>Индекс /share/</h1><ul>{items}</ul>"
    # CWE-22: Path Traversal
    filepath = os.path.join(FILES_FOLDER, filename)
    try:
        return send_file(filepath)
    except Exception as e:
        return f"Ошибка: {e}", 404


@app.route("/ping", methods=["GET", "POST"])
def ping():
    # CWE-78: OS Command Injection
    result = None
    if request.method == "POST":
        host = request.form.get("host", "127.0.0.1")
        try:
            # Намеренно небезопасно
            cmd = f"ping -n 2 {host}" if os.name == "nt" else f"ping -c 2 {host}"
            result = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT, timeout=10
            ).decode("cp866" if os.name == "nt" else "utf-8", errors="replace")
        except Exception as e:
            result = str(e)
    return render_template("ping.html", result=result)


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    # CWE-434: Unrestricted File Upload
    message = None
    files = os.listdir(UPLOAD_FOLDER)
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            path = os.path.join(UPLOAD_FOLDER, f.filename)
            f.save(path)
            message = f"Файл загружен: {f.filename}"
            files = os.listdir(UPLOAD_FOLDER)
    return render_template("upload.html", message=message, files=files)


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    # Отдача загруженных файлов без проверки типа
    return send_file(os.path.join(UPLOAD_FOLDER, filename))


@app.route("/admin")
def admin():
    # CWE-284: Broken Access Control — проверка только cookie role, без сверки с БД
    if session.get("role") != "admin":
        return "Доступ запрещён. Требуется роль admin.", 403
    db = get_db()
    users = db.execute("SELECT id, username, email, role, balance, password FROM users").fetchall()
    return render_template("admin.html", users=users)


@app.route("/api/user/<int:user_id>")
def api_user(user_id):
    # CWE-200: Information Disclosure — API без авторизации, отдаёт пароли
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return {"error": "not found"}, 404
    return {
        "id": user["id"],
        "username": user["username"],
        "password": user["password"],
        "email": user["email"],
        "role": user["role"],
        "balance": user["balance"],
    }


@app.route("/redirect")
def open_redirect():
    # CWE-601: Open Redirect
    url = request.args.get("url", "/")
    return redirect(url)


@app.after_request
def add_insecure_api_headers(resp):
    # CWE-942: Permissive CORS — "*" вместе с credentials нарушает спецификацию,
    # но на практике так настраивают реальные API
    if request.path.startswith("/api/"):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return resp


# ─── Контрольные точки (безопасные аналоги) — для проверки false positives ───


@app.route("/safe/search")
def safe_search():
    q = request.args.get("q", "")
    db = get_db()
    # Контрольная точка: параметризованный запрос — не уязвимо к SQL Injection
    products = db.execute(
        "SELECT * FROM products WHERE name LIKE ? OR description LIKE ?",
        (f"%{q}%", f"%{q}%"),
    ).fetchall()
    # q выводится через обычный Jinja2 (автоэкранирование, без |safe) — не уязвимо к XSS
    return render_template("safe.html", section="search", q=q, products=products)


@app.route("/safe/login", methods=["GET", "POST"])
def safe_login():
    error = None
    login_ok = False
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        # Контрольная точка: параметризованный запрос
        user = db.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()
        if user:
            login_ok = True
        else:
            # Контрольная точка: одно и то же сообщение независимо от причины отказа
            error = "Неверный логин или пароль"
    return render_template("safe.html", section="login", error=error, login_ok=login_ok)


@app.route("/safe/transfer", methods=["GET", "POST"])
@login_required
def safe_transfer():
    message = None
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    if request.method == "POST":
        # Контрольная точка: проверка CSRF-токена по session (hmac.compare_digest)
        token = request.form.get("csrf_token", "")
        if not hmac.compare_digest(token, session.get("csrf_token", "")):
            return "Неверный CSRF-токен", 400
        to_user = request.form.get("to_user", "")
        try:
            amount = float(request.form.get("amount", 0))
        except ValueError:
            amount = 0
        db = get_db()
        target = db.execute(
            "SELECT * FROM users WHERE username = ?", (to_user,)
        ).fetchone()
        if target and amount > 0:
            db.execute(
                "UPDATE users SET balance = balance - ? WHERE id = ?",
                (amount, session["user_id"]),
            )
            db.execute(
                "UPDATE users SET balance = balance + ? WHERE id = ?",
                (amount, target["id"]),
            )
            db.commit()
            message = f"Переведено {amount} ₽ пользователю {to_user}"
        else:
            message = "Ошибка перевода"
    return render_template(
        "safe.html", section="transfer", message=message, csrf_token=session["csrf_token"]
    )


@app.route("/safe/upload", methods=["GET", "POST"])
@login_required
def safe_upload():
    message = None
    upload_ok = False
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
            # Контрольная точка: allowlist расширений
            if ext not in ALLOWED_UPLOAD_EXT:
                message = "Недопустимый тип файла"
            else:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(0)
                # Контрольная точка: ограничение размера
                if size > MAX_SAFE_UPLOAD_SIZE:
                    message = "Файл слишком большой (лимит 2 МБ)"
                else:
                    # Контрольная точка: случайное имя файла — исходное имя не используется как путь
                    safe_name = f"{secrets.token_hex(8)}.{ext}"
                    f.save(os.path.join(UPLOAD_FOLDER, safe_name))
                    message = f"Файл загружен как {safe_name}"
                    upload_ok = True
    return render_template("safe.html", section="upload", message=message, upload_ok=upload_ok)


@app.route("/hints")
def hints():
    """Страница с подсказками для демо / презентации."""
    return render_template("hints.html")


if __name__ == "__main__":
    if not os.path.exists(DATABASE):
        init_db()
    else:
        # на случай обновления схемы в уже существующей БД демо-стенда
        try:
            conn = sqlite3.connect(DATABASE)
            conn.execute("SELECT 1 FROM orders LIMIT 1")
            conn.close()
        except sqlite3.OperationalError:
            os.remove(DATABASE)
            init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)  # CWE-489: Debug mode
