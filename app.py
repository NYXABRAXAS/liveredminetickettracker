from flask import Flask, send_from_directory, jsonify, request, session
import urllib.request
import json
import os
from concurrent.futures import ThreadPoolExecutor
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("APP_SECRET_KEY", "change-this-secret-key-before-production")
CORS(app, supports_credentials=True)

# --- CONFIGURATION ---
REDMINE_URL = "https://redmine.prohorizon.in:3000"
API_KEY = "16eac9e2365e5e3b2f398ee4b16dd30f815d2dd7"
BASE_API = f"{REDMINE_URL}/issues.json?status_id=*&key={API_KEY}"
USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")


def read_users():
    if not os.path.exists(USERS_FILE):
        return []
    with open(USERS_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)
    return data if isinstance(data, list) else []


def write_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as file:
        json.dump(users, file, indent=2)


def ensure_default_admin():
    users = read_users()
    if any(user.get("role") == "admin" for user in users):
        return

    users.append({
        "username": "admin",
        "password_hash": generate_password_hash("Admin@123"),
        "role": "admin",
        "project": "",
        "active": True
    })
    write_users(users)


def sanitize_user(user):
    return {
        "username": user["username"],
        "role": user["role"],
        "project": user.get("project", ""),
        "active": user.get("active", True)
    }


def current_user():
    username = session.get("username")
    if not username:
        return None
    for user in read_users():
        if user["username"] == username and user.get("active", True):
            return user
    return None


def require_login():
    user = current_user()
    if not user:
        return None, (jsonify({"error": "Unauthorized"}), 401)
    return user, None


def require_admin():
    user, error = require_login()
    if error:
        return None, error
    if user.get("role") != "admin":
        return None, (jsonify({"error": "Forbidden"}), 403)
    return user, None


def fetch_page(offset):
    url = f"{BASE_API}&limit=100&offset={offset}"
    try:
        with urllib.request.urlopen(url, timeout=15) as response:
            return json.loads(response.read())
    except Exception:
        return None


def fetch_all_issues():
    first_page = fetch_page(0)
    if not first_page:
        return None

    total_count = first_page.get("total_count", 0)
    all_issues = first_page.get("issues", [])
    offsets = range(100, total_count, 100)

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(fetch_page, offsets))

    for result in results:
        if result:
            all_issues.extend(result.get("issues", []))

    return all_issues


def filter_issues_for_user(issues, user, requested_project=None):
    if user.get("role") == "admin":
        if requested_project:
            requested_project_lower = requested_project.lower()
            return [
                issue for issue in issues
                if issue.get("project", {}).get("name", "").lower() == requested_project_lower
            ]
        return issues

    allowed_project = user.get("project", "").strip().lower()
    return [
        issue for issue in issues
        if issue.get("project", {}).get("name", "").lower() == allowed_project
    ]


@app.route("/api/login", methods=["POST"])
def login():
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""

    for user in read_users():
        if user["username"] != username:
            continue
        if not user.get("active", True):
            return jsonify({"error": "This user is inactive"}), 403
        if check_password_hash(user["password_hash"], password):
            session.clear()
            session["username"] = user["username"]
            return jsonify({"user": sanitize_user(user)})
        break

    return jsonify({"error": "Invalid username or password"}), 401


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/session")
def get_session():
    user = current_user()
    if not user:
        return jsonify({"user": None}), 401
    return jsonify({"user": sanitize_user(user)})


@app.route("/api/issues")
def get_issues():
    user, error = require_login()
    if error:
        return error

    issues = fetch_all_issues()
    if issues is None:
        return jsonify({"error": "Failed to fetch data from Redmine"}), 500

    requested_project = request.args.get("project", "").strip()
    visible_issues = filter_issues_for_user(issues, user, requested_project or None)
    return jsonify({
        "issues": visible_issues,
        "scope": user.get("project", "") if user.get("role") != "admin" else (requested_project or "All Projects")
    })


@app.route("/api/admin/users", methods=["GET"])
def list_users():
    _, error = require_admin()
    if error:
        return error
    users = [sanitize_user(user) for user in read_users()]
    return jsonify({"users": users})


@app.route("/api/admin/users", methods=["POST"])
def create_user():
    _, error = require_admin()
    if error:
        return error

    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    project = (payload.get("project") or "").strip()
    role = (payload.get("role") or "holder").strip().lower()

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    if role not in {"admin", "holder"}:
        return jsonify({"error": "Invalid role"}), 400
    if role != "admin" and not project:
        return jsonify({"error": "Project is required for project holders"}), 400

    users = read_users()
    if any(user["username"].lower() == username.lower() for user in users):
        return jsonify({"error": "Username already exists"}), 400

    new_user = {
        "username": username,
        "password_hash": generate_password_hash(password),
        "role": role,
        "project": "" if role == "admin" else project,
        "active": True
    }
    users.append(new_user)
    write_users(users)
    return jsonify({"user": sanitize_user(new_user)}), 201


@app.route("/api/admin/users/<username>", methods=["PATCH"])
def update_user(username):
    admin_user, error = require_admin()
    if error:
        return error

    payload = request.get_json(silent=True) or {}
    users = read_users()

    for user in users:
        if user["username"] != username:
            continue

        if "active" in payload:
            user["active"] = bool(payload["active"])
            if user["username"] == admin_user["username"] and not user["active"]:
                return jsonify({"error": "You cannot deactivate your own admin user"}), 400

        if payload.get("role") in {"admin", "holder"}:
            if user["username"] == admin_user["username"] and payload.get("role") != "admin":
                return jsonify({"error": "You cannot remove your own admin access"}), 400
            user["role"] = payload["role"]

        if "project" in payload and user.get("role") != "admin":
            user["project"] = (payload.get("project") or "").strip()
            if not user["project"]:
                return jsonify({"error": "Project is required for project holders"}), 400

        if user.get("role") == "admin":
            user["project"] = ""

        if payload.get("password"):
            user["password_hash"] = generate_password_hash(payload["password"])

        write_users(users)
        return jsonify({"user": sanitize_user(user)})

    return jsonify({"error": "User not found"}), 404


@app.route('/')
def index():
    if os.path.exists("index.html"):
        return send_from_directory('.', 'index.html')
    return send_from_directory('.', 'index (4).html')


ensure_default_admin()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
