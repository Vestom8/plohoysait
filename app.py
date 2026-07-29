"""
VulnShop — намеренно уязвимое веб-приложение для анализатора ИБ.
ТОЛЬКО для локального тестирования. Не выставлять в интернет.
"""

import os
import sqlite3
import subprocess
from functools import wraps

from flask import (
    Flask,
    g,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

app = Flask(__name__)
app.secret_key = "super-secret-key-12345"  # CWE-798: Hardcoded credentials
DATABASE = os.path.join(os.path.dirname(__file__), "vulnshop.db")
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
FILES_FOLDER = os.path.join(os.path.dirname(__file__), "files")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(FILES_FOLDER, exist_ok=True)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
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
            ('Мышь Precision', 'Игровая мышь', 2990, 'peripherals');

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


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated


# ─── Pages ───────────────────────────────────────────────────────────────────


@app.route("/")
def index():
    db = get_db()
    products = db.execute("SELECT * FROM products").fetchall()
    return render_template("index.html", products=products)


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
                return redirect(url_for("index"))
            error = "Неверный логин или пароль"
        except sqlite3.Error as e:
            error = f"Ошибка БД: {e}"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


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
    return render_template("transfer.html", message=message)


@app.route("/download")
def download():
    # CWE-22: Path Traversal
    filename = request.args.get("file", "catalog.txt")
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


@app.route("/hints")
def hints():
    """Страница с подсказками для демо / презентации."""
    return render_template("hints.html")


if __name__ == "__main__":
    if not os.path.exists(DATABASE):
        init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)  # CWE-489: Debug mode
