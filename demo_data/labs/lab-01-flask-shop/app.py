import sqlite3
from flask import Flask, request

app = Flask(__name__)
SECRET_KEY = "super-secret-demo-key-123"   # hardcoded secret (demo)

@app.route("/user")
def user():
    name = request.args.get("name")
    db = sqlite3.connect("shop.db")
    return str(db.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall())  # SQLi (demo)