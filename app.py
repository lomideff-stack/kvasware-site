"""
KvasWare — single-file Flask application.
Replaces the PHP site with identical functionality:
  - User auth (login/register/logout)
  - Dashboard with subscription management
  - Admin panel (users, subscriptions, logs)
  - API endpoints for loader (/api/auth, /api/check)
  - DLL download endpoint

Requirements:
  pip install flask

Run:
  python app.py
"""

import os
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, request, redirect, url_for, session,
    render_template_string, jsonify, send_from_directory, g
)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'kvasware-secret-key-change-this-2024')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'data', 'kvasware.db')
DLL_DIR = os.path.join(BASE_DIR, 'client_download')

SUBSCRIPTION_PLANS = {
    'day':      {'name': '1 Day',    'price': 149,  'days': 1},
    'week':     {'name': '7 Days',   'price': 499,  'days': 7},
    'month':    {'name': '30 Days',  'price': 1490, 'days': 30},
    'lifetime': {'name': 'Lifetime', 'price': 4990, 'days': 36500},
}

# ─── Database ───────────────────────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA journal_mode=WAL')
        g.db.execute('PRAGMA foreign_keys=ON')
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db:
        db.close()

def init_db():
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            hwid TEXT DEFAULT NULL,
            role TEXT DEFAULT 'user' CHECK(role IN('user','admin')),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            banned INTEGER DEFAULT 0,
            ban_reason TEXT DEFAULT NULL
        );
        CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            plan TEXT NOT NULL,
            starts_at DATETIME NOT NULL,
            expires_at DATETIME NOT NULL,
            active INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            hwid TEXT DEFAULT NULL,
            last_ip TEXT DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS activation_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            ip TEXT DEFAULT NULL,
            hwid TEXT DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    ''')
    # Create default admin
    row = db.execute("SELECT COUNT(*) as c FROM users WHERE role='admin'").fetchone()
    if row['c'] == 0:
        pw_hash = hash_password('admin')
        db.execute('INSERT INTO users (username, email, password, role) VALUES (?,?,?,?)',
                   ('admin', 'admin@kvasware.com', pw_hash, 'admin'))
        db.commit()

# ─── Helpers ────────────────────────────────────────────────────────────────

def hash_password(pw):
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100000).hex()
    return f'{salt}${h}'

def verify_password(pw, stored):
    if '$' not in stored:
        return False
    salt, h = stored.split('$', 1)
    return hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100000).hex() == h

def generate_token(user_id, hwid=None):
    token = secrets.token_hex(32)
    expires = (datetime.utcnow() + timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')
    db = get_db()
    db.execute('INSERT INTO api_tokens (user_id, token, hwid, last_ip, expires_at) VALUES (?,?,?,?,?)',
               (user_id, token, hwid, request.remote_addr, expires))
    db.commit()
    return token

def log_action(user_id, action, hwid=None):
    db = get_db()
    db.execute('INSERT INTO activation_logs (user_id, action, ip, hwid) VALUES (?,?,?,?)',
               (user_id, action, request.remote_addr, hwid))
    db.commit()

def get_active_subscription(user_id):
    db = get_db()
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    row = db.execute(
        'SELECT * FROM subscriptions WHERE user_id=? AND active=1 AND expires_at>? ORDER BY expires_at DESC LIMIT 1',
        (user_id, now)).fetchone()
    return row

def add_subscription(user_id, plan_key):
    if plan_key not in SUBSCRIPTION_PLANS:
        return False
    days = SUBSCRIPTION_PLANS[plan_key]['days']
    db = get_db()
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    existing = db.execute(
        'SELECT expires_at FROM subscriptions WHERE user_id=? AND active=1 AND expires_at>? ORDER BY expires_at DESC LIMIT 1',
        (user_id, now)).fetchone()
    if existing:
        base = datetime.strptime(existing['expires_at'], '%Y-%m-%d %H:%M:%S')
    else:
        base = datetime.utcnow()
    expires = (base + timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
    db.execute('INSERT INTO subscriptions (user_id, plan, starts_at, expires_at) VALUES (?,?,?,?)',
               (user_id, plan_key, now, expires))
    db.commit()
    return True

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

def current_user():
    if 'user_id' not in session:
        return None
    db = get_db()
    return db.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()

# ─── Auth Routes ────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    error = ''
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        if user and verify_password(password, user['password']) and not user['banned']:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        error = 'Неверный логин или пароль'
    return render_template_string(LOGIN_HTML, error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    error = ''
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        if len(username) < 3 or len(username) > 24:
            error = 'Логин должен быть 3-24 символа'
        elif len(password) < 6:
            error = 'Пароль минимум 6 символов'
        else:
            db = get_db()
            if db.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone():
                error = 'Логин занят'
            elif db.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone():
                error = 'Email уже зарегистрирован'
            else:
                pw_hash = hash_password(password)
                db.execute('INSERT INTO users (username, email, password) VALUES (?,?,?)',
                           (username, email, pw_hash))
                db.commit()
                user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                return redirect(url_for('dashboard'))
    return render_template_string(REGISTER_HTML, error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ─── Dashboard ──────────────────────────────────────────────────────────────

@app.route('/')
def landing():
    return render_template_string(LANDING_HTML)

@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user()
    db = get_db()
    active_sub = get_active_subscription(user['id'])
    subscriptions = db.execute('SELECT * FROM subscriptions WHERE user_id=? ORDER BY created_at DESC', (user['id'],)).fetchall()
    api_tokens = db.execute('SELECT * FROM api_tokens WHERE user_id=? ORDER BY created_at DESC', (user['id'],)).fetchall()
    page = request.args.get('page', 'dashboard')
    msg = request.args.get('msg', '')
    msg_type = request.args.get('type', 'success')
    return render_template_string(DASHBOARD_HTML,
        user=user, active_sub=active_sub, subscriptions=subscriptions,
        api_tokens=api_tokens, page=page, msg=msg, msg_type=msg_type,
        plans=SUBSCRIPTION_PLANS, is_admin=(session.get('role')=='admin'))

@app.route('/dashboard/action', methods=['POST'])
@login_required
def dashboard_action():
    user = current_user()
    action = request.form.get('action', '')
    if action == 'generate_token':
        hwid = request.form.get('hwid', '') or None
        generate_token(user['id'], hwid)
        log_action(user['id'], 'token_generated', hwid)
        return redirect(url_for('dashboard', page='keys', msg='Токен создан', type='success'))
    if action == 'revoke_token':
        token = request.form.get('token', '')
        db = get_db()
        db.execute('DELETE FROM api_tokens WHERE token=? AND user_id=?', (token, user['id']))
        db.commit()
        log_action(user['id'], 'token_revoked')
        return redirect(url_for('dashboard', page='keys', msg='Токен отозван', type='success'))
    if action == 'activate_key':
        key = request.form.get('key', '').strip().lower()
        if key in SUBSCRIPTION_PLANS:
            add_subscription(user['id'], key)
            log_action(user['id'], 'subscription_activated')
            return redirect(url_for('dashboard', msg='Подписка активирована!', type='success'))
        return redirect(url_for('dashboard', msg='Неверный ключ', type='danger'))
    return redirect(url_for('dashboard'))

# ─── Admin ──────────────────────────────────────────────────────────────────

@app.route('/admin')
@admin_required
def admin_panel():
    db = get_db()
    page = request.args.get('page', 'dashboard')
    msg = request.args.get('msg', '')
    msg_type = request.args.get('type', 'success')
    users = db.execute('''SELECT *, (SELECT COUNT(*) FROM subscriptions
        WHERE user_id=users.id AND active=1 AND expires_at>datetime('now')) as has_sub
        FROM users ORDER BY created_at DESC''').fetchall()
    all_subs = db.execute('''SELECT s.*, u.username FROM subscriptions s
        JOIN users u ON s.user_id=u.id ORDER BY s.created_at DESC LIMIT 50''').fetchall()
    logs = db.execute('''SELECT l.*, u.username FROM activation_logs l
        JOIN users u ON l.user_id=u.id ORDER BY l.created_at DESC LIMIT 50''').fetchall()
    total_users = db.execute('SELECT COUNT(*) as c FROM users').fetchone()['c']
    active_subs = db.execute("SELECT COUNT(*) as c FROM subscriptions WHERE active=1 AND expires_at>datetime('now')").fetchone()['c']
    active_tokens = db.execute("SELECT COUNT(*) as c FROM api_tokens WHERE expires_at>datetime('now')").fetchone()['c']
    return render_template_string(ADMIN_HTML,
        page=page, msg=msg, msg_type=msg_type, users=users,
        all_subs=all_subs, logs=logs, total_users=total_users,
        active_subs=active_subs, active_tokens=active_tokens, plans=SUBSCRIPTION_PLANS)

@app.route('/admin/action', methods=['POST'])
@admin_required
def admin_action():
    db = get_db()
    action = request.form.get('action', '')
    if action == 'add_sub':
        uid = int(request.form.get('user_id', 0))
        plan = request.form.get('plan', '')
        if uid and plan in SUBSCRIPTION_PLANS:
            add_subscription(uid, plan)
        return redirect(url_for('admin_panel', page='users', msg='Подписка добавлена', type='success'))
    if action == 'ban_user':
        uid = int(request.form.get('user_id', 0))
        reason = request.form.get('reason', '')
        db.execute('UPDATE users SET banned=1, ban_reason=? WHERE id=?', (reason, uid))
        db.commit()
        return redirect(url_for('admin_panel', page='users', msg='Пользователь забанен', type='success'))
    if action == 'unban_user':
        uid = int(request.form.get('user_id', 0))
        db.execute('UPDATE users SET banned=0, ban_reason=NULL WHERE id=?', (uid,))
        db.commit()
        return redirect(url_for('admin_panel', page='users', msg='Пользователь разбанен', type='success'))
    if action == 'delete_sub':
        sid = int(request.form.get('sub_id', 0))
        db.execute('DELETE FROM subscriptions WHERE id=?', (sid,))
        db.commit()
        return redirect(url_for('admin_panel', page='subscriptions', msg='Подписка удалена', type='success'))
    return redirect(url_for('admin_panel'))

# ─── API Endpoints (for loader) ────────────────────────────────────────────

@app.route('/api/auth.php', methods=['POST', 'OPTIONS'])
@app.route('/api/auth', methods=['POST', 'OPTIONS'])
def api_auth():
    if request.method == 'OPTIONS':
        return '', 204
    data = request.get_json(silent=True) or request.form
    username = data.get('username', '')
    password = data.get('password', '')
    hwid = data.get('hwid', '')
    if not username or not password:
        return jsonify(status='error', message='Username and password required')
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    if not user or not verify_password(password, user['password']):
        return jsonify(status='error', message='Invalid credentials')
    if user['banned']:
        return jsonify(status='error', message='Account banned', ban_reason=user['ban_reason'])
    token = generate_token(user['id'], hwid)
    log_action(user['id'], 'auth', hwid)
    db.execute('UPDATE users SET hwid=? WHERE id=?', (hwid, user['id']))
    db.commit()
    sub = get_active_subscription(user['id'])
    sub_data = None
    if sub:
        sub_data = {'plan': sub['plan'], 'active': True, 'expires_at': sub['expires_at'],
                    'days_left': max(0, (datetime.strptime(sub['expires_at'], '%Y-%m-%d %H:%M:%S') - datetime.utcnow()).days)}
    return jsonify(status='success', user_id=user['id'], username=user['username'],
                   role=user['role'], token=token, subscription=sub_data)

@app.route('/api/check.php', methods=['POST', 'GET', 'OPTIONS'])
@app.route('/api/check', methods=['POST', 'GET', 'OPTIONS'])
def api_check():
    if request.method == 'OPTIONS':
        return '', 204
    token = ''
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        token = auth_header[7:]
    if not token:
        data = request.get_json(silent=True) or {}
        token = data.get('token', '') or request.args.get('token', '')
    if not token:
        return jsonify(status='error', message='Token required')
    db = get_db()
    row = db.execute('''SELECT t.*, u.username, u.role, u.banned FROM api_tokens t
        JOIN users u ON t.user_id=u.id WHERE t.token=?''', (token,)).fetchone()
    if not row:
        return jsonify(status='error', message='Invalid token')
    if datetime.strptime(row['expires_at'], '%Y-%m-%d %H:%M:%S') < datetime.utcnow():
        db.execute('DELETE FROM api_tokens WHERE token=?', (token,))
        db.commit()
        return jsonify(status='error', message='Token expired')
    if row['banned']:
        return jsonify(status='error', message='Account banned')
    data = request.get_json(silent=True) or {}
    hwid = data.get('hwid', '') or request.args.get('hwid', '')
    if hwid and row['hwid'] and hwid != row['hwid']:
        return jsonify(status='error', message='HWID mismatch')
    db.execute('UPDATE api_tokens SET last_ip=? WHERE token=?', (request.remote_addr, token))
    new_exp = (datetime.utcnow() + timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')
    db.execute('UPDATE api_tokens SET expires_at=? WHERE token=?', (new_exp, token))
    db.commit()
    sub = get_active_subscription(row['user_id'])
    log_action(row['user_id'], 'check', hwid)
    sub_data = {'plan': None, 'active': False, 'expires_at': None, 'days_left': 0}
    if sub:
        sub_data = {'plan': sub['plan'], 'active': True, 'expires_at': sub['expires_at'],
                    'days_left': max(0, (datetime.strptime(sub['expires_at'], '%Y-%m-%d %H:%M:%S') - datetime.utcnow()).days)}
    return jsonify(status='success', user_id=row['user_id'], username=row['username'],
                   role=row['role'], subscription=sub_data)

@app.route('/client_download/<filename>')
def download_file(filename):
    if not os.path.exists(os.path.join(DLL_DIR, filename)):
        return 'Not found', 404
    return send_from_directory(DLL_DIR, filename)

# ─── Templates ──────────────────────────────────────────────────────────────

LANDING_HTML = '''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KvasWare — ALT:V / Majestic Roleplay</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
:root {
  --white: #ffffff;
  --bg: #f8f8fc;
  --bg2: #f0f0f8;
  --text: #0a0a14;
  --text2: #5a5a7a;
  --text3: #9090aa;
  --accent: #6c5ce7;
  --accent2: #a29bfe;
  --border: rgba(0,0,0,0.07);
  --shadow: 0 2px 20px rgba(0,0,0,0.06);
  --shadow-lg: 0 8px 48px rgba(108,92,231,0.12);
  --radius: 16px;
}
html { scroll-behavior: smooth; }
body { font-family: 'Inter', sans-serif; background: var(--white); color: var(--text); -webkit-font-smoothing: antialiased; }
a { text-decoration: none; color: inherit; }

/* ── Nav ── */
nav {
  position: fixed; top: 0; left: 0; right: 0; z-index: 100;
  background: rgba(255,255,255,0.85);
  backdrop-filter: blur(20px);
  border-bottom: 1px solid var(--border);
  padding: 0 40px;
  height: 64px;
  display: flex; align-items: center; justify-content: space-between;
}
.nav-logo { display: flex; align-items: center; gap: 10px; font-size: 18px; font-weight: 800; letter-spacing: -0.3px; }
.nav-logo-icon {
  width: 36px; height: 36px;
  background: linear-gradient(135deg, var(--accent), var(--accent2));
  border-radius: 10px;
  display: flex; align-items: center; justify-content: center;
}
.nav-logo-icon svg { width: 20px; height: 20px; }
.nav-links { display: flex; align-items: center; gap: 32px; }
.nav-links a { font-size: 14px; font-weight: 500; color: var(--text2); transition: color .2s; }
.nav-links a:hover { color: var(--text); }
.nav-cta { display: flex; gap: 10px; }
.btn { display: inline-flex; align-items: center; gap: 8px; padding: 9px 20px; border-radius: 10px; font-size: 14px; font-weight: 600; font-family: inherit; border: none; cursor: pointer; transition: all .2s; }
.btn-ghost { background: transparent; color: var(--text2); }
.btn-ghost:hover { background: var(--bg); color: var(--text); }
.btn-primary { background: var(--accent); color: #fff; box-shadow: 0 4px 16px rgba(108,92,231,0.25); }
.btn-primary:hover { transform: translateY(-1px); box-shadow: 0 6px 24px rgba(108,92,231,0.35); }
.btn-lg { padding: 14px 32px; font-size: 15px; border-radius: 12px; }
.btn-outline { background: transparent; color: var(--accent); border: 1.5px solid var(--accent); }
.btn-outline:hover { background: var(--accent); color: #fff; }

/* ── Hero ── */
.hero {
  padding: 160px 40px 100px;
  text-align: center;
  max-width: 900px;
  margin: 0 auto;
}
.hero-badge {
  display: inline-flex; align-items: center; gap: 8px;
  background: linear-gradient(135deg, rgba(108,92,231,0.08), rgba(162,155,254,0.08));
  border: 1px solid rgba(108,92,231,0.2);
  color: var(--accent);
  padding: 6px 16px;
  border-radius: 100px;
  font-size: 13px; font-weight: 600;
  margin-bottom: 28px;
}
.hero-badge span { width: 6px; height: 6px; background: var(--accent); border-radius: 50%; display: inline-block; }
.hero h1 {
  font-size: clamp(42px, 6vw, 72px);
  font-weight: 900;
  letter-spacing: -2px;
  line-height: 1.05;
  margin-bottom: 24px;
  color: var(--text);
}
.hero h1 em { font-style: normal; color: var(--accent); }
.hero p {
  font-size: 18px; color: var(--text2); line-height: 1.7;
  max-width: 560px; margin: 0 auto 40px;
}
.hero-btns { display: flex; gap: 12px; justify-content: center; flex-wrap: wrap; }
.hero-stats {
  display: flex; gap: 48px; justify-content: center;
  margin-top: 72px; padding-top: 48px;
  border-top: 1px solid var(--border);
}
.stat-num { font-size: 32px; font-weight: 800; letter-spacing: -1px; color: var(--text); }
.stat-label { font-size: 13px; color: var(--text3); margin-top: 4px; }

/* ── Features ── */
.section { padding: 100px 40px; max-width: 1100px; margin: 0 auto; }
.section-label { font-size: 12px; font-weight: 700; color: var(--accent); text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 12px; }
.section-title { font-size: clamp(28px, 4vw, 42px); font-weight: 800; letter-spacing: -1px; margin-bottom: 16px; }
.section-sub { font-size: 16px; color: var(--text2); max-width: 480px; line-height: 1.6; }
.features-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-top: 56px; }
.feature-card {
  background: var(--white);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 28px;
  transition: all .25s;
  box-shadow: var(--shadow);
}
.feature-card:hover { transform: translateY(-4px); box-shadow: var(--shadow-lg); border-color: rgba(108,92,231,0.2); }
.feature-icon {
  width: 48px; height: 48px;
  background: linear-gradient(135deg, rgba(108,92,231,0.1), rgba(162,155,254,0.1));
  border-radius: 12px;
  display: flex; align-items: center; justify-content: center;
  margin-bottom: 20px;
}
.feature-icon svg { width: 24px; height: 24px; color: var(--accent); }
.feature-card h3 { font-size: 16px; font-weight: 700; margin-bottom: 8px; }
.feature-card p { font-size: 14px; color: var(--text2); line-height: 1.6; }

/* ── Pricing ── */
.pricing-section { background: var(--bg); padding: 100px 40px; }
.pricing-inner { max-width: 1000px; margin: 0 auto; }
.pricing-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-top: 56px; }
.price-card {
  background: var(--white);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 28px 24px;
  text-align: center;
  transition: all .25s;
  box-shadow: var(--shadow);
  position: relative;
}
.price-card.popular {
  border-color: var(--accent);
  box-shadow: 0 8px 40px rgba(108,92,231,0.15);
  transform: scale(1.03);
}
.popular-badge {
  position: absolute; top: -12px; left: 50%; transform: translateX(-50%);
  background: var(--accent); color: #fff;
  font-size: 11px; font-weight: 700; padding: 4px 14px; border-radius: 100px;
  white-space: nowrap;
}
.price-name { font-size: 13px; font-weight: 700; color: var(--text3); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 16px; }
.price-amount { font-size: 36px; font-weight: 900; letter-spacing: -1px; color: var(--text); }
.price-amount span { font-size: 16px; font-weight: 500; color: var(--text3); }
.price-period { font-size: 13px; color: var(--text3); margin-top: 4px; margin-bottom: 24px; }
.price-card .btn { width: 100%; justify-content: center; }

/* ── CTA ── */
.cta-section {
  padding: 100px 40px;
  text-align: center;
  background: linear-gradient(135deg, #f0eeff, #e8e4ff);
}
.cta-section h2 { font-size: clamp(28px, 4vw, 48px); font-weight: 900; letter-spacing: -1.5px; margin-bottom: 16px; }
.cta-section p { font-size: 16px; color: var(--text2); margin-bottom: 36px; }

/* ── Footer ── */
footer {
  background: var(--text);
  color: rgba(255,255,255,0.5);
  padding: 48px 40px;
}
.footer-inner { max-width: 1100px; margin: 0 auto; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 24px; }
.footer-logo { display: flex; align-items: center; gap: 10px; color: #fff; font-size: 16px; font-weight: 700; }
.footer-logo-icon { width: 32px; height: 32px; background: linear-gradient(135deg, var(--accent), var(--accent2)); border-radius: 8px; display: flex; align-items: center; justify-content: center; }
.footer-logo-icon svg { width: 18px; height: 18px; }
.footer-links { display: flex; gap: 24px; }
.footer-links a { font-size: 14px; color: rgba(255,255,255,0.4); transition: color .2s; }
.footer-links a:hover { color: #fff; }
.social-links { display: flex; gap: 12px; }
.social-btn {
  width: 40px; height: 40px;
  background: rgba(255,255,255,0.08);
  border-radius: 10px;
  display: flex; align-items: center; justify-content: center;
  transition: all .2s;
  color: rgba(255,255,255,0.5);
}
.social-btn:hover { background: var(--accent); color: #fff; transform: translateY(-2px); }
.social-btn svg { width: 18px; height: 18px; }
.footer-copy { font-size: 13px; color: rgba(255,255,255,0.25); margin-top: 32px; text-align: center; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 24px; }

@media (max-width: 900px) {
  .features-grid { grid-template-columns: 1fr 1fr; }
  .pricing-grid { grid-template-columns: 1fr 1fr; }
  .price-card.popular { transform: none; }
  .hero-stats { gap: 32px; }
}
@media (max-width: 600px) {
  nav { padding: 0 20px; }
  .nav-links { display: none; }
  .hero { padding: 120px 20px 80px; }
  .section { padding: 72px 20px; }
  .features-grid { grid-template-columns: 1fr; }
  .pricing-grid { grid-template-columns: 1fr; }
  .hero-stats { flex-direction: column; gap: 24px; }
  .footer-inner { flex-direction: column; align-items: flex-start; }
}
</style>
</head>
<body>

<!-- Nav -->
<nav>
  <div class="nav-logo">
    <div class="nav-logo-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
    </div>
    KvasWare
  </div>
  <div class="nav-links">
    <a href="#features">Возможности</a>
    <a href="#pricing">Цены</a>
    <a href="https://t.me/kvasware" target="_blank">Telegram</a>
  </div>
  <div class="nav-cta">
    <a href="/login" class="btn btn-ghost">Войти</a>
    <a href="/register" class="btn btn-primary">Начать</a>
  </div>
</nav>

<!-- Hero -->
<section class="hero">
  <div class="hero-badge"><span></span> ALT:V · Majestic Roleplay · Undetect с 02.05.2026</div>
  <h1>Чит для <em>ALT:V</em><br>Majestic Roleplay</h1>
  <p>KvasWare — приватный чит под ALT:V и Majestic Roleplay. Аимбот, ESP, защита и десятки функций. 100 пользователей, ни одного бана.</p>
  <div class="hero-btns">
    <a href="/register" class="btn btn-primary btn-lg">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:18px;height:18px"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
      Попробовать
    </a>
    <a href="https://t.me/kvasware" target="_blank" class="btn btn-outline btn-lg">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:18px;height:18px"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
      Telegram
    </a>
  </div>
  <div class="hero-stats">
    <div>
      <div class="stat-num">100</div>
      <div class="stat-label">Пользователей</div>
    </div>
    <div>
      <div class="stat-num">Undetect</div>
      <div class="stat-label">с 02.05.2026</div>
    </div>
    <div>
      <div class="stat-num">0</div>
      <div class="stat-label">Банов</div>
    </div>
  </div>
</section>

<!-- Features -->
<section class="section" id="features">
  <div class="section-label">Возможности</div>
  <div class="section-title">Всё что нужно</div>
  <div class="section-sub">Полный набор инструментов для комфортной игры в GTA V.</div>
  <div class="features-grid">
    <div class="feature-card">
      <div class="feature-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/></svg>
      </div>
      <h3>Аимбот</h3>
      <p>Плавный и точный аимбот с настройкой FOV, скорости и кости цели. Работает через стены.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
      </div>
      <h3>ESP</h3>
      <p>Отображение игроков, транспорта и предметов через стены. Настраиваемые цвета и дистанция.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      </div>
      <h3>Защита</h3>
      <p>Защита от кика, спуфинг режима бога, блокировка принудительного выхода из машины.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
      </div>
      <h3>Меню</h3>
      <p>Красивый ImGui интерфейс с поддержкой тем, горячих клавиш и сохранением конфигов.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
      </div>
      <h3>Быстрый инжект</h3>
      <p>Manual map инжект без следов в списке модулей. Работает с GTA V, FiveM и RageMP.</p>
    </div>
    <div class="feature-card">
      <div class="feature-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
      </div>
      <h3>Авто-обновления</h3>
      <p>Лоадер автоматически скачивает актуальную версию при каждом запуске.</p>
    </div>
  </div>
</section>

<!-- Pricing -->
<div class="pricing-section" id="pricing">
  <div class="pricing-inner">
    <div class="section-label">Цены</div>
    <div class="section-title">Выберите тариф</div>
    <div class="section-sub">Доступные цены без скрытых платежей.</div>
    <div class="pricing-grid">
      <div class="price-card">
        <div class="price-name">День</div>
        <div class="price-amount">149<span> ₽</span></div>
        <div class="price-period">1 день доступа</div>
        <a href="/register" class="btn btn-outline">Купить</a>
      </div>
      <div class="price-card popular">
        <div class="popular-badge">Популярно</div>
        <div class="price-name">Неделя</div>
        <div class="price-amount">499<span> ₽</span></div>
        <div class="price-period">7 дней доступа</div>
        <a href="/register" class="btn btn-primary">Купить</a>
      </div>
      <div class="price-card">
        <div class="price-name">Месяц</div>
        <div class="price-amount">1490<span> ₽</span></div>
        <div class="price-period">30 дней доступа</div>
        <a href="/register" class="btn btn-outline">Купить</a>
      </div>
      <div class="price-card">
        <div class="price-name">Навсегда</div>
        <div class="price-amount">4990<span> ₽</span></div>
        <div class="price-period">Пожизненный доступ</div>
        <a href="/register" class="btn btn-outline">Купить</a>
      </div>
    </div>
  </div>
</div>

<!-- CTA -->
<section class="cta-section">
  <h2>Готов начать?</h2>
  <p>Зарегистрируйся и получи доступ уже через минуту.</p>
  <a href="/register" class="btn btn-primary btn-lg">Создать аккаунт</a>
</section>

<!-- Footer -->
<footer>
  <div class="footer-inner">
    <div class="footer-logo">
      <div class="footer-logo-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
      </div>
      KvasWare
    </div>
    <div class="footer-links">
      <a href="#features">Возможности</a>
      <a href="#pricing">Цены</a>
      <a href="/login">Войти</a>
      <a href="/register">Регистрация</a>
    </div>
    <div class="social-links">
      <a href="https://t.me/kvasware" target="_blank" class="social-btn" title="Telegram">
        <svg viewBox="0 0 24 24" fill="currentColor"><path d="M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z"/></svg>
      </a>
    </div>
  </div>
  <div class="footer-copy">© 2026 KvasWare. Только для образовательных целей.</div>
</footer>

</body>
</html>'''

STYLE = '''
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
:root {
  --bg: #08080f;
  --bg2: #0e0e1a;
  --bg3: #16162a;
  --bg4: #1e1e35;
  --accent: #7c6af7;
  --accent2: #a78bfa;
  --accent-glow: rgba(124,106,247,0.18);
  --accent-border: rgba(124,106,247,0.35);
  --text: #f0f0ff;
  --text2: #9090b8;
  --text3: #55556a;
  --border: rgba(255,255,255,0.07);
  --border2: rgba(255,255,255,0.12);
  --success: #34d399;
  --success-bg: rgba(52,211,153,0.1);
  --success-border: rgba(52,211,153,0.25);
  --danger: #f87171;
  --danger-bg: rgba(248,113,113,0.1);
  --danger-border: rgba(248,113,113,0.25);
  --info: #60a5fa;
  --info-bg: rgba(96,165,250,0.1);
  --warn: #fbbf24;
  --radius: 14px;
  --radius-sm: 8px;
  --shadow: 0 4px 24px rgba(0,0,0,0.4);
  --shadow-lg: 0 8px 48px rgba(0,0,0,0.6);
}
html { font-size: 15px; }
body {
  font-family: 'Inter', -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  -webkit-font-smoothing: antialiased;
}
a { color: var(--accent2); text-decoration: none; transition: color .2s; }
a:hover { color: var(--text); }
::selection { background: var(--accent-glow); }
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: var(--bg2); }
::-webkit-scrollbar-thumb { background: var(--bg4); border-radius: 3px; }

/* ── Auth ── */
.auth-page {
  min-height: 100vh;
  display: grid;
  grid-template-columns: 1fr 1fr;
  background: var(--bg);
}
.auth-left {
  position: relative;
  background: linear-gradient(145deg, #0d0b2e 0%, #1a0a3e 50%, #0f1a3e 100%);
  display: flex;
  flex-direction: column;
  justify-content: center;
  padding: 64px;
  overflow: hidden;
}
.auth-left::before {
  content: '';
  position: absolute;
  width: 500px; height: 500px;
  background: radial-gradient(circle, rgba(124,106,247,0.15) 0%, transparent 70%);
  top: -100px; left: -100px;
  pointer-events: none;
}
.auth-left::after {
  content: '';
  position: absolute;
  width: 300px; height: 300px;
  background: radial-gradient(circle, rgba(167,139,250,0.1) 0%, transparent 70%);
  bottom: 50px; right: 50px;
  pointer-events: none;
}
.auth-logo {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 56px;
}
.auth-logo-icon {
  width: 44px; height: 44px;
  background: linear-gradient(135deg, var(--accent), var(--accent2));
  border-radius: 12px;
  display: flex; align-items: center; justify-content: center;
  box-shadow: 0 0 24px var(--accent-glow);
}
.auth-logo-icon svg { width: 24px; height: 24px; }
.auth-logo-name { font-size: 20px; font-weight: 700; color: #fff; letter-spacing: -0.3px; }
.auth-left h2 { font-size: 36px; font-weight: 800; color: #fff; line-height: 1.2; margin-bottom: 16px; letter-spacing: -0.5px; }
.auth-left p { font-size: 15px; color: rgba(255,255,255,0.5); line-height: 1.6; max-width: 320px; }
.auth-dots {
  display: flex; gap: 8px; margin-top: 48px;
}
.auth-dots span {
  width: 8px; height: 8px; border-radius: 50%;
  background: rgba(255,255,255,0.15);
}
.auth-dots span:first-child { background: var(--accent); width: 24px; border-radius: 4px; }
.auth-right {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 48px;
  background: var(--bg);
}
.auth-box {
  width: 100%;
  max-width: 400px;
}
.auth-box h1 { font-size: 26px; font-weight: 800; margin-bottom: 6px; letter-spacing: -0.3px; }
.auth-box .sub { color: var(--text2); font-size: 14px; margin-bottom: 32px; }
.form-group { margin-bottom: 18px; }
.form-group label { display: block; font-size: 12px; font-weight: 600; color: var(--text2); margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
.form-control {
  width: 100%;
  padding: 12px 16px;
  background: var(--bg3);
  border: 1px solid var(--border2);
  border-radius: var(--radius-sm);
  color: var(--text);
  font-size: 14px;
  font-family: inherit;
  outline: none;
  transition: border-color .2s, box-shadow .2s;
}
.form-control:focus {
  border-color: var(--accent-border);
  box-shadow: 0 0 0 3px var(--accent-glow);
}
.form-control::placeholder { color: var(--text3); }
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 11px 22px;
  border-radius: var(--radius-sm);
  font-size: 14px;
  font-weight: 600;
  font-family: inherit;
  border: none;
  cursor: pointer;
  transition: all .2s;
  white-space: nowrap;
}
.btn-primary {
  background: linear-gradient(135deg, var(--accent), #6d5ce7);
  color: #fff;
  box-shadow: 0 4px 16px rgba(124,106,247,0.3);
}
.btn-primary:hover { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(124,106,247,0.4); }
.btn-primary:active { transform: translateY(0); }
.btn-danger { background: var(--danger-bg); color: var(--danger); border: 1px solid var(--danger-border); }
.btn-danger:hover { background: var(--danger); color: #fff; }
.btn-success { background: var(--success-bg); color: var(--success); border: 1px solid var(--success-border); }
.btn-success:hover { background: var(--success); color: #fff; }
.btn-ghost { background: var(--bg3); color: var(--text2); border: 1px solid var(--border2); }
.btn-ghost:hover { background: var(--bg4); color: var(--text); }
.btn-sm { padding: 7px 14px; font-size: 12px; border-radius: 6px; }
.btn-lg { padding: 14px 28px; font-size: 15px; }
.btn-full { width: 100%; }
.alert {
  padding: 13px 16px;
  border-radius: var(--radius-sm);
  font-size: 13px;
  margin-bottom: 20px;
  display: flex;
  align-items: center;
  gap: 10px;
}
.alert-success { background: var(--success-bg); color: var(--success); border: 1px solid var(--success-border); }
.alert-danger { background: var(--danger-bg); color: var(--danger); border: 1px solid var(--danger-border); }
.auth-footer { margin-top: 28px; text-align: center; color: var(--text3); font-size: 13px; }
.auth-footer a { color: var(--accent2); font-weight: 500; }

/* ── Dashboard layout ── */
.app { display: flex; min-height: 100vh; }
.sidebar {
  width: 248px;
  min-width: 248px;
  background: var(--bg2);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  padding: 24px 16px;
  position: sticky;
  top: 0;
  height: 100vh;
  overflow-y: auto;
}
.sidebar-logo {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 4px 8px 28px;
}
.sidebar-logo-icon {
  width: 36px; height: 36px;
  background: linear-gradient(135deg, var(--accent), var(--accent2));
  border-radius: 10px;
  display: flex; align-items: center; justify-content: center;
  flex-shrink: 0;
}
.sidebar-logo-icon svg { width: 20px; height: 20px; }
.sidebar-logo-name { font-size: 16px; font-weight: 700; letter-spacing: -0.2px; }
.nav-section { margin-bottom: 4px; }
.nav-label { font-size: 10px; font-weight: 700; color: var(--text3); text-transform: uppercase; letter-spacing: 1px; padding: 0 12px; margin-bottom: 6px; margin-top: 16px; }
.nav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 12px;
  border-radius: var(--radius-sm);
  color: var(--text2);
  font-size: 13.5px;
  font-weight: 500;
  margin-bottom: 2px;
  transition: all .15s;
  cursor: pointer;
}
.nav-item svg { width: 17px; height: 17px; flex-shrink: 0; }
.nav-item:hover { background: var(--bg3); color: var(--text); }
.nav-item.active { background: var(--accent-glow); color: var(--accent2); border: 1px solid var(--accent-border); }
.sidebar-footer { margin-top: auto; padding-top: 16px; border-top: 1px solid var(--border); }
.sidebar-user {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: background .15s;
}
.sidebar-user:hover { background: var(--bg3); }
.sidebar-avatar {
  width: 32px; height: 32px;
  background: linear-gradient(135deg, var(--accent), var(--accent2));
  border-radius: 8px;
  display: flex; align-items: center; justify-content: center;
  font-size: 13px; font-weight: 700; color: #fff;
  flex-shrink: 0;
}
.sidebar-user-info { flex: 1; min-width: 0; }
.sidebar-user-name { font-size: 13px; font-weight: 600; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.sidebar-user-role { font-size: 11px; color: var(--text3); }
.main { flex: 1; padding: 36px 40px; overflow-y: auto; min-width: 0; }
.page-header { margin-bottom: 28px; }
.page-title { font-size: 22px; font-weight: 800; letter-spacing: -0.3px; }
.page-sub { color: var(--text2); font-size: 13px; margin-top: 4px; }

/* ── Cards ── */
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 28px; }
.card {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 22px;
  transition: border-color .2s;
}
.card:hover { border-color: var(--border2); }
.card-icon {
  width: 40px; height: 40px;
  border-radius: 10px;
  display: flex; align-items: center; justify-content: center;
  margin-bottom: 16px;
}
.card-icon svg { width: 20px; height: 20px; }
.card-label { font-size: 11px; font-weight: 600; color: var(--text3); text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 6px; }
.card-value { font-size: 26px; font-weight: 800; letter-spacing: -0.5px; }
.card-value.ok { color: var(--success); }
.card-value.no { color: var(--danger); }
.card-hint { font-size: 12px; color: var(--text3); margin-top: 4px; }

/* ── Table ── */
.table-wrap {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
  margin-bottom: 28px;
}
.table-wrap table { width: 100%; border-collapse: collapse; }
.table-wrap th {
  padding: 12px 16px;
  font-size: 11px;
  font-weight: 700;
  color: var(--text3);
  text-transform: uppercase;
  letter-spacing: 0.8px;
  background: var(--bg3);
  border-bottom: 1px solid var(--border);
  text-align: left;
}
.table-wrap td {
  padding: 13px 16px;
  font-size: 13px;
  color: var(--text2);
  border-bottom: 1px solid var(--border);
  vertical-align: middle;
}
.table-wrap tr:last-child td { border-bottom: none; }
.table-wrap tr:hover td { background: rgba(255,255,255,0.02); }
.table-wrap td strong { color: var(--text); font-weight: 600; }
.table-empty { text-align: center; color: var(--text3); padding: 40px !important; }

/* ── Badges ── */
.badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 10px;
  border-radius: 20px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.2px;
}
.badge-success { background: var(--success-bg); color: var(--success); border: 1px solid var(--success-border); }
.badge-danger { background: var(--danger-bg); color: var(--danger); border: 1px solid var(--danger-border); }
.badge-info { background: var(--info-bg); color: var(--info); border: 1px solid rgba(96,165,250,0.25); }
.badge-warn { background: rgba(251,191,36,0.1); color: var(--warn); border: 1px solid rgba(251,191,36,0.25); }
.badge-dot::before { content: ''; width: 6px; height: 6px; border-radius: 50%; background: currentColor; display: inline-block; }

/* ── Status box ── */
.status-box {
  border-radius: var(--radius);
  padding: 20px 24px;
  margin-bottom: 24px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}
.status-box.ok { background: var(--success-bg); border: 1px solid var(--success-border); }
.status-box.no { background: var(--danger-bg); border: 1px solid var(--danger-border); }
.status-box-title { font-size: 15px; font-weight: 700; margin-bottom: 3px; }
.status-box.ok .status-box-title { color: var(--success); }
.status-box.no .status-box-title { color: var(--danger); }
.status-box-sub { font-size: 13px; color: var(--text2); }

/* ── Section ── */
.section { margin-bottom: 32px; }
.section-title { font-size: 14px; font-weight: 700; color: var(--text); margin-bottom: 14px; display: flex; align-items: center; gap: 8px; }
.section-title::after { content: ''; flex: 1; height: 1px; background: var(--border); }

/* ── Input row ── */
.input-row { display: flex; gap: 10px; align-items: flex-end; flex-wrap: wrap; }
.input-row .form-control { max-width: 300px; }

/* ── Download card ── */
.dl-card {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 48px;
  text-align: center;
  max-width: 480px;
}
.dl-icon {
  width: 72px; height: 72px;
  background: var(--accent-glow);
  border: 1px solid var(--accent-border);
  border-radius: 20px;
  display: flex; align-items: center; justify-content: center;
  margin: 0 auto 24px;
}
.dl-icon svg { width: 36px; height: 36px; color: var(--accent2); }
.dl-card h2 { font-size: 20px; font-weight: 800; margin-bottom: 8px; }
.dl-card p { color: var(--text2); font-size: 14px; margin-bottom: 28px; line-height: 1.6; }

/* ── Mono ── */
.mono { font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 12px; }

/* ── Select ── */
select {
  padding: 8px 12px;
  background: var(--bg3);
  border: 1px solid var(--border2);
  border-radius: 6px;
  color: var(--text);
  font-size: 12px;
  font-family: inherit;
  outline: none;
  cursor: pointer;
}
select:focus { border-color: var(--accent-border); }

/* ── Responsive ── */
@media (max-width: 900px) {
  .auth-page { grid-template-columns: 1fr; }
  .auth-left { display: none; }
  .sidebar { width: 200px; min-width: 200px; }
  .main { padding: 24px 20px; }
}
@media (max-width: 640px) {
  .sidebar { display: none; }
  .main { padding: 20px 16px; }
  .cards { grid-template-columns: 1fr 1fr; }
}
</style>
'''

LOGIN_HTML = '''<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Вход — KvasWare</title>''' + STYLE + '''</head><body>
<div class="auth-page">
  <div class="auth-left">
    <div class="auth-logo">
      <div class="auth-logo-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
      </div>
      <span class="auth-logo-name">KvasWare</span>
    </div>
    <h2>С возвращением</h2>
    <p>Войдите в личный кабинет, чтобы управлять подпиской и скачать чит.</p>
    <div class="auth-dots"><span></span><span></span><span></span></div>
  </div>
  <div class="auth-right">
    <div class="auth-box">
      <h1>Вход в аккаунт</h1>
      <p class="sub">Введите данные для входа</p>
      {% if error %}<div class="alert alert-danger">{{ error }}</div>{% endif %}
      <form method="POST">
        <div class="form-group">
          <label>Логин</label>
          <input type="text" name="username" class="form-control" placeholder="Ваш логин" required autofocus>
        </div>
        <div class="form-group">
          <label>Пароль</label>
          <input type="password" name="password" class="form-control" placeholder="Ваш пароль" required>
        </div>
        <button type="submit" class="btn btn-primary btn-lg btn-full" style="margin-top:8px">Войти</button>
      </form>
      <div class="auth-footer">Нет аккаунта? <a href="/register">Зарегистрироваться</a></div>
    </div>
  </div>
</div>
</body></html>'''

REGISTER_HTML = '''<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Регистрация — KvasWare</title>''' + STYLE + '''</head><body>
<div class="auth-page">
  <div class="auth-left">
    <div class="auth-logo">
      <div class="auth-logo-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
      </div>
      <span class="auth-logo-name">KvasWare</span>
    </div>
    <h2>Присоединяйтесь</h2>
    <p>Создайте аккаунт и получите доступ к KvasWare уже сегодня.</p>
    <div class="auth-dots"><span></span><span></span><span></span></div>
  </div>
  <div class="auth-right">
    <div class="auth-box">
      <h1>Создать аккаунт</h1>
      <p class="sub">Заполните форму ниже</p>
      {% if error %}<div class="alert alert-danger">{{ error }}</div>{% endif %}
      <form method="POST">
        <div class="form-group">
          <label>Логин</label>
          <input type="text" name="username" class="form-control" placeholder="3–24 символа" required minlength="3" maxlength="24">
        </div>
        <div class="form-group">
          <label>Email</label>
          <input type="email" name="email" class="form-control" placeholder="you@example.com" required>
        </div>
        <div class="form-group">
          <label>Пароль</label>
          <input type="password" name="password" class="form-control" placeholder="Минимум 6 символов" required minlength="6">
        </div>
        <button type="submit" class="btn btn-primary btn-lg btn-full" style="margin-top:8px">Создать аккаунт</button>
      </form>
      <div class="auth-footer">Уже есть аккаунт? <a href="/login">Войти</a></div>
    </div>
  </div>
</div>
</body></html>'''

DASHBOARD_HTML = '''<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Кабинет — KvasWare</title>''' + STYLE + '''</head><body>
<div class="app">
  <aside class="sidebar">
    <div class="sidebar-logo">
      <div class="sidebar-logo-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
      </div>
      <span class="sidebar-logo-name">KvasWare</span>
    </div>
    <div class="nav-section">
      <div class="nav-label">Меню</div>
      <a href="/dashboard" class="nav-item {{ 'active' if page=='dashboard' else '' }}">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
        Главная
      </a>
      <a href="/dashboard?page=subscription" class="nav-item {{ 'active' if page=='subscription' else '' }}">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
        Подписка
      </a>
      <a href="/dashboard?page=download" class="nav-item {{ 'active' if page=='download' else '' }}">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        Скачать
      </a>
      {% if is_admin %}
      <div class="nav-label" style="margin-top:20px">Администратор</div>
      <a href="/admin" class="nav-item">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        Панель админа
      </a>
      {% endif %}
    </div>
    <div class="sidebar-footer">
      <a href="/logout" class="sidebar-user">
        <div class="sidebar-avatar">{{ user['username'][0]|upper }}</div>
        <div class="sidebar-user-info">
          <div class="sidebar-user-name">{{ user['username'] }}</div>
          <div class="sidebar-user-role">{{ 'Администратор' if user['role']=='admin' else 'Пользователь' }}</div>
        </div>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:15px;height:15px;color:var(--text3);flex-shrink:0"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      </a>
    </div>
  </aside>

  <main class="main">
    {% if msg %}
    <div class="alert alert-{{ msg_type }}" style="margin-bottom:24px">{{ msg }}</div>
    {% endif %}

    {% if page == 'dashboard' %}
    <div class="page-header">
      <div class="page-title">Добро пожаловать, {{ user['username'] }}</div>
      <div class="page-sub">Обзор вашего аккаунта</div>
    </div>
    <div class="cards">
      <div class="card">
        <div class="card-icon" style="background:{{ 'var(--success-bg)' if active_sub else 'var(--danger-bg)' }}">
          <svg viewBox="0 0 24 24" fill="none" stroke="{{ '#34d399' if active_sub else '#f87171' }}" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
        </div>
        <div class="card-label">Подписка</div>
        <div class="card-value {{ 'ok' if active_sub else 'no' }}">{{ 'Активна' if active_sub else 'Нет' }}</div>
        <div class="card-hint">{{ ('До ' + active_sub['expires_at'][:10]) if active_sub else 'Нет активной подписки' }}</div>
      </div>
      <div class="card">
        <div class="card-icon" style="background:var(--accent-glow)">
          <svg viewBox="0 0 24 24" fill="none" stroke="var(--accent2)" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
        </div>
        <div class="card-label">Тариф</div>
        <div class="card-value" style="font-size:20px">{{ active_sub['plan']|upper if active_sub else '—' }}</div>
        <div class="card-hint">{{ plans[active_sub['plan']]['name'] if active_sub and active_sub['plan'] in plans else 'Нет тарифа' }}</div>
      </div>
      <div class="card">
        <div class="card-icon" style="background:var(--info-bg)">
          <svg viewBox="0 0 24 24" fill="none" stroke="var(--info)" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
        </div>
        <div class="card-label">HWID</div>
        <div class="card-value mono" style="font-size:13px;letter-spacing:0">{{ (user['hwid'] or 'Не привязан')[:14] }}</div>
        <div class="card-hint">Привязка устройства</div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">Активация ключа</div>
      <form method="POST" action="/dashboard/action" class="input-row">
        <input type="hidden" name="action" value="activate_key">
        <input type="text" name="key" class="form-control" placeholder="Введите ключ активации">
        <button type="submit" class="btn btn-primary">Активировать</button>
      </form>
    </div>

    <div class="section">
      <div class="section-title">История подписок</div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Дата</th><th>Тариф</th><th>Истекает</th><th>Статус</th></tr></thead>
          <tbody>
          {% for s in subscriptions[:5] %}
          <tr>
            <td>{{ s['created_at'][:10] }}</td>
            <td><strong>{{ plans[s['plan']]['name'] if s['plan'] in plans else s['plan'] }}</strong></td>
            <td>{{ s['expires_at'][:16] }}</td>
            <td><span class="badge badge-dot badge-{{ 'success' if s['active'] else 'danger' }}">{{ 'Активна' if s['active'] else 'Истекла' }}</span></td>
          </tr>
          {% else %}
          <tr><td colspan="4" class="table-empty">Подписок пока нет</td></tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    </div>

    {% elif page == 'subscription' %}
    <div class="page-header">
      <div class="page-title">Подписка</div>
      <div class="page-sub">Управление вашей подпиской</div>
    </div>
    <div class="status-box {{ 'ok' if active_sub else 'no' }}">
      <div>
        <div class="status-box-title">{{ 'Подписка активна' if active_sub else 'Нет активной подписки' }}</div>
        <div class="status-box-sub">{{ ('Тариф ' + (plans[active_sub['plan']]['name'] if active_sub['plan'] in plans else active_sub['plan']) + ' — до ' + active_sub['expires_at'][:16]) if active_sub else 'Активируйте ключ ниже' }}</div>
      </div>
      <span class="badge badge-dot badge-{{ 'success' if active_sub else 'danger' }}">{{ 'Активна' if active_sub else 'Неактивна' }}</span>
    </div>
    <div class="section">
      <div class="section-title">Активация ключа</div>
      <form method="POST" action="/dashboard/action" class="input-row">
        <input type="hidden" name="action" value="activate_key">
        <input type="text" name="key" class="form-control" placeholder="Введите ключ активации">
        <button type="submit" class="btn btn-primary">Активировать</button>
      </form>
    </div>

    {% elif page == 'download' %}
    <div class="page-header">
      <div class="page-title">Скачать</div>
      <div class="page-sub">Загрузка лоадера KvasWare</div>
    </div>
    {% if active_sub %}
    <div class="dl-card">
      <div class="dl-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
      </div>
      <h2>KvasWare Loader</h2>
      <p>Скачайте лоадер, запустите от имени администратора и войдите в свой аккаунт.</p>
      <a href="/client_download/kvasware.exe" class="btn btn-primary btn-lg">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:18px;height:18px"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        Скачать лоадер
      </a>
    </div>
    {% else %}
    <div class="status-box no">
      <div>
        <div class="status-box-title">Нет активной подписки</div>
        <div class="status-box-sub">Для скачивания необходима активная подписка</div>
      </div>
      <a href="/dashboard?page=subscription" class="btn btn-primary btn-sm">Активировать</a>
    </div>
    {% endif %}
    {% endif %}
  </main>
</div>
</body></html>'''

ADMIN_HTML = '''<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Админ — KvasWare</title>''' + STYLE + '''</head><body>
<div class="app">
  <aside class="sidebar">
    <div class="sidebar-logo">
      <div class="sidebar-logo-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      </div>
      <span class="sidebar-logo-name">Админ</span>
    </div>
    <div class="nav-section">
      <div class="nav-label">Управление</div>
      <a href="/admin?page=dashboard" class="nav-item {{ 'active' if page=='dashboard' else '' }}">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
        Обзор
      </a>
      <a href="/admin?page=users" class="nav-item {{ 'active' if page=='users' else '' }}">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
        Пользователи
      </a>
      <a href="/admin?page=subscriptions" class="nav-item {{ 'active' if page=='subscriptions' else '' }}">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
        Подписки
      </a>
      <a href="/admin?page=logs" class="nav-item {{ 'active' if page=='logs' else '' }}">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
        Логи
      </a>
    </div>
    <div class="sidebar-footer">
      <a href="/dashboard" class="nav-item">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>
        Назад в кабинет
      </a>
    </div>
  </aside>

  <main class="main">
    {% if msg %}
    <div class="alert alert-{{ msg_type }}" style="margin-bottom:24px">{{ msg }}</div>
    {% endif %}

    {% if page == 'dashboard' %}
    <div class="page-header">
      <div class="page-title">Панель администратора</div>
      <div class="page-sub">Общая статистика системы</div>
    </div>
    <div class="cards">
      <div class="card">
        <div class="card-icon" style="background:var(--info-bg)">
          <svg viewBox="0 0 24 24" fill="none" stroke="var(--info)" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg>
        </div>
        <div class="card-label">Пользователей</div>
        <div class="card-value">{{ total_users }}</div>
      </div>
      <div class="card">
        <div class="card-icon" style="background:var(--success-bg)">
          <svg viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
        </div>
        <div class="card-label">Активных подписок</div>
        <div class="card-value ok">{{ active_subs }}</div>
      </div>
      <div class="card">
        <div class="card-icon" style="background:var(--accent-glow)">
          <svg viewBox="0 0 24 24" fill="none" stroke="var(--accent2)" stroke-width="2"><circle cx="8" cy="15" r="4"/><path d="M11.7 11.3L22 1"/></svg>
        </div>
        <div class="card-label">Активных токенов</div>
        <div class="card-value">{{ active_tokens }}</div>
      </div>
    </div>

    {% elif page == 'users' %}
    <div class="page-header">
      <div class="page-title">Пользователи</div>
      <div class="page-sub">Управление аккаунтами</div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>ID</th><th>Логин</th><th>Email</th><th>Роль</th><th>Подписка</th><th>Статус</th><th>Дата</th><th>Действия</th></tr></thead>
        <tbody>
        {% for u in users %}
        <tr>
          <td style="color:var(--text3)">{{ u['id'] }}</td>
          <td><strong>{{ u['username'] }}</strong></td>
          <td>{{ u['email'] }}</td>
          <td><span class="badge badge-{{ 'warn' if u['role']=='admin' else 'info' }}">{{ 'Админ' if u['role']=='admin' else 'Юзер' }}</span></td>
          <td><span class="badge badge-dot badge-{{ 'success' if u['has_sub'] else 'danger' }}">{{ 'Есть' if u['has_sub'] else 'Нет' }}</span></td>
          <td><span class="badge badge-dot badge-{{ 'danger' if u['banned'] else 'success' }}">{{ 'Бан' if u['banned'] else 'OK' }}</span></td>
          <td>{{ u['created_at'][:10] }}</td>
          <td>
            <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
              <form method="POST" action="/admin/action" style="display:flex;gap:6px;align-items:center">
                <input type="hidden" name="action" value="add_sub">
                <input type="hidden" name="user_id" value="{{ u['id'] }}">
                <select name="plan">{% for pk,pl in plans.items() %}<option value="{{ pk }}">{{ pl['name'] }}</option>{% endfor %}</select>
                <button class="btn btn-success btn-sm">+ Подписка</button>
              </form>
              {% if u['banned'] %}
              <form method="POST" action="/admin/action">
                <input type="hidden" name="action" value="unban_user">
                <input type="hidden" name="user_id" value="{{ u['id'] }}">
                <button class="btn btn-ghost btn-sm">Разбанить</button>
              </form>
              {% else %}
              <form method="POST" action="/admin/action" style="display:flex;gap:6px;align-items:center">
                <input type="hidden" name="action" value="ban_user">
                <input type="hidden" name="user_id" value="{{ u['id'] }}">
                <input type="text" name="reason" placeholder="Причина" class="form-control" style="width:90px;padding:6px 10px;font-size:12px">
                <button class="btn btn-danger btn-sm">Бан</button>
              </form>
              {% endif %}
            </div>
          </td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>

    {% elif page == 'subscriptions' %}
    <div class="page-header">
      <div class="page-title">Подписки</div>
      <div class="page-sub">Все подписки в системе</div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>ID</th><th>Пользователь</th><th>Тариф</th><th>Истекает</th><th>Статус</th><th></th></tr></thead>
        <tbody>
        {% for s in all_subs %}
        <tr>
          <td style="color:var(--text3)">{{ s['id'] }}</td>
          <td><strong>{{ s['username'] }}</strong></td>
          <td>{{ plans[s['plan']]['name'] if s['plan'] in plans else s['plan'] }}</td>
          <td>{{ s['expires_at'][:16] }}</td>
          <td><span class="badge badge-dot badge-{{ 'success' if s['active'] else 'danger' }}">{{ 'Активна' if s['active'] else 'Истекла' }}</span></td>
          <td>
            <form method="POST" action="/admin/action">
              <input type="hidden" name="action" value="delete_sub">
              <input type="hidden" name="sub_id" value="{{ s['id'] }}">
              <button class="btn btn-danger btn-sm">Удалить</button>
            </form>
          </td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>

    {% elif page == 'logs' %}
    <div class="page-header">
      <div class="page-title">Логи активности</div>
      <div class="page-sub">Последние 50 событий</div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Дата</th><th>Пользователь</th><th>Действие</th><th>IP</th><th>HWID</th></tr></thead>
        <tbody>
        {% for l in logs %}
        <tr>
          <td>{{ l['created_at'][:16] }}</td>
          <td><strong>{{ l['username'] }}</strong></td>
          <td><span class="badge badge-info">{{ l['action'] }}</span></td>
          <td>{{ l['ip'] or '—' }}</td>
          <td class="mono">{{ (l['hwid'] or '—')[:18] }}</td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
    {% endif %}
  </main>
</div>
</body></html>'''

# ─── Init & Run ─────────────────────────────────────────────────────────────

with app.app_context():
    init_db()

if __name__ == '__main__':
    os.makedirs(DLL_DIR, exist_ok=True)
    # Railway предоставляет порт через переменную окружения $PORT
    PORT = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=PORT, debug=False)
