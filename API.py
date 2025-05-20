from flask import Flask, request, jsonify, make_response
import os, sqlite3, bcrypt, uuid, jwt, datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from dotenv import load_dotenv

app = Flask(__name__)
limiter = Limiter(key_func=get_remote_address)

load_dotenv()
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
if not app.config['SECRET_KEY']:
    raise ValueError("A SECRET_KEY környezeti változó nincs megadva!")

secret_key = app.config["SECRET_KEY"]

def get_db_connection():
    conn = sqlite3.connect("adatbazis.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        points INTEGER DEFAULT 0,
        admin BOOLEAN DEFAULT 0
    )
    """)

    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        hash = bcrypt.hashpw("admin".encode("UTF-8"), bcrypt.gensalt()).decode("UTF-8")
        cursor.execute("INSERT INTO users (name, username, password, admin) VALUES (?, ?, ?, ?)", ("admin", "admin", hash, True))
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blacklist (
        token TEXT PRIMARY KEY
    )
    """)
    
    conn.commit()
    conn.close()

def token_szukseges(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("access_token")
        if token:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM blacklist WHERE token = ?", (token, ))
            if not cursor.fetchone():
                try: decoded = jwt.decode(token, secret_key, algorithms = ["HS256"])
                except jwt.ExpiredSignatureError:
                    try:
                        refresh_token = request.cookies.get("refresh_token")
                        decoded_rf = jwt.decode(refresh_token, secret_key, algorithms = ["HS256"])
                        username = decoded_rf.get("username")

                        conn = get_db_connection()
                        cursor = conn.cursor()
                        cursor.execute("SELECT * FROM users WHERE username = ?", (username, ))
                        felh = cursor.fetchone()
                        conn.close()

                        token = jwt.encode({"id": felh["id"], "admin": felh["admin"],"exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, secret_key, algorithm="HS256")
                        decoded = jwt.decode(token, secret_key, algorithms = ["HS256"])
                        response = make_response(f(decoded, *args, **kwargs))

                        response.set_cookie("access_token", token, httponly=True, secure=False, samesite="Lax")
                        response.set_cookie("refresh_token", refresh_token, httponly=True, secure=False, samesite="Lax")
                        return response
                    except jwt.ExpiredSignatureError:
                        return jsonify({"message": "A folytatáshoz újboli bejelentkezés szükséges!"}), 401
                    except jwt.InvalidTokenError:
                        return jsonify({"message": "Érvénytelen token!"}), 401
                except jwt.InvalidTokenError:
                    return jsonify({"message": "Érvénytelen token!"}), 401
                return f(decoded, *args, **kwargs)
            return jsonify({"message": "A folytatáshoz bejelentkezés szükséges!"}), 401
        return jsonify({"message": "A folytatáshoz bejelentkezés szükséges!"}), 401
    return decorated

@app.errorhandler(429)
def rate_limit_error(e):
    return jsonify({"error": "Túl sok hibás próbálkozás. Kérlek próbáld meg később!"}), 429

@app.route('/create-user', methods=["POST"])
@token_szukseges
def create_user(decoded_token):
    if decoded_token.get("admin"):
        data = request.get_json()
        name = data.get("name")
        passw = data.get("password")
        username = data.get("username")
        admin = bool(data.get("admin"))
        if all([username, passw, name]):
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            if not cursor.fetchone():
                hash = bcrypt.hashpw(passw.encode("UTF-8"), bcrypt.gensalt()).decode("UTF-8")
                cursor.execute("INSERT INTO users (name, username, password, admin) VALUES (?, ?, ?, ?)", (name, username, hash, admin))
                conn.commit()
                conn.close()
                return jsonify({"message": "A felhasználó sikeresen létre hozva!"}), 201
            return jsonify({"message": "Ez a felhasználó már szerepel!!"}), 400
        return jsonify({"message": "Hiányzó adatok"}), 400
    return jsonify({"message": "Nincs jogosultságodhozzá!"}), 403

@app.route('/login', methods=["POST"])
@limiter.limit("3 per minutes")
def login():
    data = request.get_json()
    username = data.get("username")
    passw = data.get("password")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username, ))
    felh = cursor.fetchone()
    conn.close()

    if all([username, passw]):
        if felh:
            felh_user = felh["username"]
            felh_pass = felh["password"]
            if bcrypt.checkpw(passw.encode("UTF-8"), felh_pass.encode("utf-8")) and felh_user == username:
                token = jwt.encode({"id": felh["id"], "admin": felh["admin"],"exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, secret_key, algorithm="HS256")
                refresh_token = jwt.encode({"id": felh["id"], "admin": felh["admin"],"exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)}, secret_key, algorithm="HS256")
                response = make_response(jsonify({"message": "Sikeres bejelentkezés! Üdvözöljük!"}))

                response.set_cookie("access_token", token, httponly=True, secure=False, samesite="Lax")
                response.set_cookie("refresh_token", refresh_token, httponly=True, secure=False, samesite="Lax")
                return response, 200
            return jsonify({"message": "Hibás felhasználónév vagy jelszó."}), 400
        return jsonify({"message": "Ez a felhasználó nem létezik..."}), 404
    return jsonify({"message": "Hiányzó adatok!!"}), 400

@app.route('/logout', methods=["POST"])
@token_szukseges
def logout(decoded_token):
    token = request.cookies.get("access_token")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO blacklist (token) VALUES (?)", (token, ))
    conn.commit()
    conn.close()

    return jsonify({"message": "Sikeres kijelentkezés!"}), 200

@app.route('/available-users', methods=["GET"])
def available_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name, points FROM users ORDER BY name ASC")
    adatok = cursor.fetchall()
    conn.close()
    return jsonify([dict(i) for i in adatok]), 200

@app.route("/admin/change-password/<int:id>", methods=["PUT"])
@token_szukseges
def ad_pass_ch(decoded_token):
    if decoded_token.get("admin"):
        data = request.get_json()
        username = data.get("username")
        passw = data.get("password")
        new_passw = data.get("new_password")
        if all([username, passw, new_passw]):
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT password FROM users WHERE username = ?", (username, ))
            felh = cursor.fetchone()
            if felh:
                if bcrypt.checkpw(passw.encode("utf-8"), felh["password"].encode("utf-8")):
                    cursor.execute("UPDATE users SET password = ? WHERE username = ?", (bcrypt.hashpw(new_passw.encode("UTF-8"), bcrypt.gensalt()).decode("UTF-8"), username))
                    conn.commit()
                    conn.close()
                    return jsonify({"message": "Sikeres jelszó módosítás!"}), 200
                return jsonify({"message": "Hibás jelszó!"}), 403
            return jsonify({"message": "Nics ilyen felhasználó"}), 404
        return jsonify({"message": "Hiányzó adatok!"}), 400
    return jsonify({"message": "Nincs jogosultságod hozzá!"}), 403

@app.route("/change-password", methods=["PUT"])
@token_szukseges
def self_pass_ch(decoded_token):
    data = request.get_json()
    passw = data.get("password")
    new_passw = data.get("new_password")
    token = request.cookies.get("access_token")
    if all([new_passw, passw]):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE id = ?", (decoded_token.get("id"), ))
        felh = cursor.fetchone()
        if felh:
            if bcrypt.checkpw(passw.encode("utf-8"), felh["password"].encode("utf-8")):
                if not bcrypt.checkpw(new_passw.encode("utf-8"), felh["password"].encode("utf-8")):
                    cursor.execute("UPDATE users SET password = ? WHERE id = ?", (bcrypt.hashpw(new_passw.encode("UTF-8"), bcrypt.gensalt()).decode("UTF-8"), decoded_token.get("id")))
                    cursor.execute("INSERT INTO blacklist (token) VALUES (?)", (token, ))
                    conn.commit()
                    conn.close()
                    return jsonify({"message": "Sikeres jelszó változtatás!\nKilettél jelentkeztetve!"}), 200
                return jsonify({"message": "Az új jelszó nem lehet egyenlő az eddigivel!"}), 400
            return jsonify({"message": "Hibás jelszó!"}), 403
        return jsonify({"message": "A felhasználó nem található!"}), 404
    return jsonify({"message": "Hiányzó adatok!"}), 400

@app.route("/main/<int:id>", methods=["DELETE"])
@token_szukseges
def delete_user(decoded_token, id):
    if decoded_token.get("admin"):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (id, ))
        if cursor.fetchone():
            cursor.execute("DELETE FROM users WHERE id = ?", (id, ))
            conn.commit()
            conn.close()
            return jsonify({"message": "Sikeres törlés."}), 200
        return jsonify({"message": "A felhasználó nem létezik."}), 404
    return jsonify({"message": "Nincs jogosultságod hozzá!"}), 403

if __name__ == '__main__':
    if not os.path.exists("adatbazis.db"):
        init_db()
    app.run(debug=True, port=5001)