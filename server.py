import http.server
import socketserver
import os
import sys
import re
import json
import time
import sqlite3
import hashlib
import secrets
import smtplib
import threading
import urllib.request
import urllib.error
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, parse_qs

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'pos_saas.db')
CONFIG_PATH = os.path.join(BASE_DIR, 'config.json')
PORT = int(os.environ.get('PORT', 8080))

SUBSCRIPTION_PRICE = 10000
SUBSCRIPTION_DAYS = 90  # 3 meses
DEFAULT_TRIAL_DAYS = 3  # 3 días de prueba gratis automática al registrarse

DATABASE_URL = os.environ.get('DATABASE_URL', '').strip()
IS_POSTGRES = bool(DATABASE_URL)


def utc_now():
    return datetime.now(timezone.utc)


def slugify(text):
    s = (text or '').strip().lower()
    replacements = {'á': 'a', 'é': 'e', 'í': 'i', 'ó': 'o', 'ú': 'u', 'ñ': 'n', 'ü': 'u'}
    for k, v in replacements.items():
        s = s.replace(k, v)
    s = re.sub(r'[^a-z0-9]+', '-', s).strip('-')
    return s or ('tienda-' + secrets.token_hex(3))


def hash_password(password, salt=None):
    if not salt:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac('sha256', str(password).encode('utf-8'), salt.encode('utf-8'), 120000)
    return f"{salt}${dk.hex()}"


def verify_password(password, stored_hash):
    if not stored_hash or '$' not in stored_hash:
        return False
    try:
        salt, _ = stored_hash.split('$', 1)
        return secrets.compare_digest(hash_password(str(password), salt), stored_hash)
    except Exception:
        return False


class PgCursorWrapper:
    def __init__(self, cur):
        self._cur = cur
        self.lastrowid = None

    def execute(self, sql, params=()):
        q = sql.replace('?', '%s')
        if 'INSERT OR IGNORE INTO' in q:
            q = q.replace('INSERT OR IGNORE INTO', 'INSERT INTO') + ' ON CONFLICT DO NOTHING'
        want_id = q.lstrip().upper().startswith('INSERT INTO USERS ')
        if want_id and 'RETURNING' not in q.upper():
            q = q.rstrip().rstrip(';') + ' RETURNING id'
        self._cur.execute(q, params)
        if want_id:
            row = self._cur.fetchone()
            if row:
                self.lastrowid = row['id'] if isinstance(row, dict) else row[0]
        return self

    def executescript(self, script):
        pg_sql = script.replace('INTEGER PRIMARY KEY AUTOINCREMENT', 'SERIAL PRIMARY KEY')
        for stmt in pg_sql.split(';'):
            s = stmt.strip()
            if s:
                self._cur.execute(s)

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()


class PgConnWrapper:
    def __init__(self, dsn):
        import psycopg2
        import psycopg2.extras
        self._conn = psycopg2.connect(dsn, cursor_factory=psycopg2.extras.RealDictCursor)

    def cursor(self):
        return PgCursorWrapper(self._conn.cursor())

    def execute(self, sql, params=()):
        cur = self.cursor()
        cur.execute(sql, params)
        return cur

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


def get_db():
    if IS_POSTGRES:
        return PgConnWrapper(DATABASE_URL)
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    conn.row_factory = sqlite3.Row
    return conn


def load_config(conn=None):
    cfg = {
        "PLATFORM_MP_ACCESS_TOKEN": os.environ.get("PLATFORM_MP_ACCESS_TOKEN", ""),
        "PLATFORM_MP_PAY_LINK": os.environ.get("PLATFORM_MP_PAY_LINK", ""),
        "PUBLIC_BASE_URL": os.environ.get("PUBLIC_BASE_URL", "") or os.environ.get("RENDER_EXTERNAL_URL", ""),
        "ADMIN_EMAIL": os.environ.get("ADMIN_EMAIL", "admin@comprobantespos.com"),
        "ADMIN_PASSWORD": os.environ.get("ADMIN_PASSWORD", "admin1234"),
        "TRIAL_DAYS": str(os.environ.get("TRIAL_DAYS", DEFAULT_TRIAL_DAYS)),
        "SMTP_HOST": os.environ.get("SMTP_HOST", ""),
        "SMTP_PORT": os.environ.get("SMTP_PORT", "587"),
        "SMTP_USER": os.environ.get("SMTP_USER", ""),
        "SMTP_PASS": os.environ.get("SMTP_PASS", ""),
    }
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                saved = json.load(f)
                cfg.update({k: v for k, v in saved.items() if v is not None and v != ""})
        except Exception:
            pass

    own_conn = False
    if conn is None:
        try:
            conn = get_db()
            own_conn = True
        except Exception:
            conn = None

    if conn is not None:
        try:
            rows = conn.execute('SELECT key, value FROM platform_settings').fetchall()
            for r in rows:
                if r['value'] is not None and r['value'] != '':
                    cfg[r['key']] = r['value']
        except Exception:
            if IS_POSTGRES:
                try:
                    conn.rollback()
                except Exception:
                    pass
        finally:
            if own_conn:
                conn.close()
    return cfg


def save_config(new_cfg, conn=None):
    own_conn = False
    if conn is None:
        conn = get_db()
        own_conn = True
    try:
        for k, v in new_cfg.items():
            if v is None:
                continue
            conn.execute(
                '''INSERT INTO platform_settings (key, value) VALUES (?, ?)
                   ON CONFLICT(key) DO UPDATE SET value = excluded.value''',
                (str(k), str(v))
            )
        conn.commit()
    finally:
        if own_conn:
            conn.close()

    try:
        cfg = load_config()
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def ensure_unique_slug(conn, desired_slug, exclude_user_id=None):
    base = slugify(desired_slug)
    candidate = base
    counter = 2
    while True:
        if exclude_user_id is not None:
            row = conn.execute(
                'SELECT user_id FROM store_profiles WHERE slug = ? AND user_id != ?',
                (candidate, exclude_user_id)
            ).fetchone()
        else:
            row = conn.execute('SELECT user_id FROM store_profiles WHERE slug = ?', (candidate,)).fetchone()
        if not row:
            return candidate
        candidate = f"{base}-{counter}"
        counter += 1


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS platform_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            recovery_pin_hash TEXT DEFAULT '',
            role TEXT DEFAULT 'merchant',
            store_name TEXT NOT NULL,
            subscription_status TEXT DEFAULT 'pending',
            subscription_expires_at TEXT,
            is_trial INTEGER DEFAULT 0,
            mp_last_payment_id TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            scope TEXT DEFAULT 'owner',
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS password_resets (
            email TEXT PRIMARY KEY,
            code_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS store_profiles (
            user_id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            slug TEXT DEFAULT '',
            store_icon TEXT DEFAULT '🛍️',
            logo_data_url TEXT DEFAULT '',
            receipt_theme TEXT DEFAULT 'coquette',
            app_palette TEXT DEFAULT 'violet',
            custom_color TEXT DEFAULT '#7C3AED',
            business_mode TEXT DEFAULT 'NUEVO PEDIDO PARA DESPACHO',
            phone TEXT DEFAULT '',
            address TEXT DEFAULT '',
            instagram TEXT DEFAULT '',
            website TEXT DEFAULT '',
            currency_symbol TEXT DEFAULT '$',
            next_folio_number INTEGER DEFAULT 1001,
            receipt_footer_message TEXT DEFAULT '¡Muchas gracias por tu compra! 💖 Preparamos tu pedido con mucho cuidado para despacharlo pronto.',
            mp_access_token TEXT DEFAULT '',
            staff_pin TEXT DEFAULT '',
            voice_accent TEXT DEFAULT 'argentina',
            voice_template TEXT DEFAULT '¡Pago confirmado! {nombre} abonó {monto} por Mercado Pago.',
            voice_enabled INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS products (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            cost_price REAL DEFAULT 0,
            category TEXT DEFAULT 'General',
            stock INTEGER DEFAULT 10,
            min_stock INTEGER DEFAULT 3,
            barcode TEXT DEFAULT '',
            sku TEXT DEFAULT '',
            image_url TEXT DEFAULT '',
            variants_json TEXT DEFAULT '[]',
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS customers (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            phone TEXT DEFAULT '',
            address TEXT DEFAULT '',
            handle TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS orders (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            tracking_code TEXT UNIQUE NOT NULL,
            folio_number TEXT NOT NULL,
            customer_name TEXT NOT NULL,
            customer_phone TEXT DEFAULT '',
            customer_address TEXT DEFAULT '',
            customer_handle TEXT DEFAULT '',
            items_json TEXT NOT NULL,
            subtotal REAL NOT NULL,
            discount_amount REAL DEFAULT 0,
            discount_label TEXT DEFAULT '',
            total REAL NOT NULL,
            total_cost REAL DEFAULT 0,
            net_profit REAL DEFAULT 0,
            payment_status TEXT DEFAULT 'pending',
            mp_payment_id TEXT DEFAULT '',
            mp_payment_link TEXT DEFAULT '',
            dispatch_status TEXT DEFAULT 'to_prepare',
            shipping_carrier TEXT DEFAULT '',
            shipping_tracking TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            source TEXT DEFAULT 'pos',
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS expenses (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            category TEXT DEFAULT 'Operativo',
            description TEXT NOT NULL,
            amount REAL NOT NULL,
            expense_date TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS subscription_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            mp_payment_id TEXT UNIQUE,
            amount REAL NOT NULL,
            status TEXT NOT NULL,
            raw_json TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    ''')
    conn.commit()

    # Safe migrations for existing databases
    migrations = [
        "ALTER TABLE users ADD COLUMN recovery_pin_hash TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN is_trial INTEGER DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN scope TEXT DEFAULT 'owner'",
        "ALTER TABLE products ADD COLUMN cost_price REAL DEFAULT 0",
        "ALTER TABLE products ADD COLUMN image_url TEXT DEFAULT ''",
        "ALTER TABLE products ADD COLUMN variants_json TEXT DEFAULT '[]'",
        "ALTER TABLE orders ADD COLUMN total_cost REAL DEFAULT 0",
        "ALTER TABLE orders ADD COLUMN net_profit REAL DEFAULT 0",
        "ALTER TABLE orders ADD COLUMN source TEXT DEFAULT 'pos'",
        "ALTER TABLE store_profiles ADD COLUMN app_palette TEXT DEFAULT 'violet'",
        "ALTER TABLE store_profiles ADD COLUMN custom_color TEXT DEFAULT '#7C3AED'",
        "ALTER TABLE store_profiles ADD COLUMN business_mode TEXT DEFAULT 'NUEVO PEDIDO PARA DESPACHO'",
        "ALTER TABLE store_profiles ADD COLUMN slug TEXT DEFAULT ''",
        "ALTER TABLE store_profiles ADD COLUMN staff_pin TEXT DEFAULT ''",
    ]
    for alter_sql in migrations:
        try:
            c.execute(alter_sql)
            conn.commit()
        except Exception:
            if IS_POSTGRES:
                conn.rollback()

    # Populate missing slugs on existing store_profiles
    missing_slugs = conn.execute("SELECT user_id, name FROM store_profiles WHERE slug IS NULL OR slug = ''").fetchall()
    for row in missing_slugs:
        new_slug = ensure_unique_slug(conn, row['name'], row['user_id'])
        conn.execute('UPDATE store_profiles SET slug = ? WHERE user_id = ?', (new_slug, row['user_id']))
    conn.commit()

    # Ensure default admin user exists
    cfg = load_config(conn)
    admin_email = cfg['ADMIN_EMAIL'].strip().lower()
    existing = c.execute('SELECT id FROM users WHERE email = ?', (admin_email,)).fetchone()
    if not existing:
        now_iso = utc_now().isoformat()
        exp_iso = (utc_now() + timedelta(days=3650)).isoformat()
        c.execute(
            '''INSERT INTO users (email, password_hash, recovery_pin_hash, role, store_name, subscription_status, subscription_expires_at, created_at)
               VALUES (?, ?, ?, 'admin', 'Admin Central POS', 'active', ?, ?)''',
            (admin_email, hash_password(cfg['ADMIN_PASSWORD']), hash_password('0000'), exp_iso, now_iso)
        )
        admin_id = c.lastrowid
        admin_slug = ensure_unique_slug(conn, 'admin-central-pos', admin_id)
        c.execute('INSERT INTO store_profiles (user_id, name, slug) VALUES (?, ?, ?)', (admin_id, 'Admin Central POS', admin_slug))
        conn.commit()

    conn.close()


def mp_api_request(method, path, token, payload=None):
    url = f"https://api.mercadopago.com{path}"
    data = json.dumps(payload).encode('utf-8') if payload is not None else None
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'User-Agent': 'VentaFlowPOS-SaaS/3.0'
    }
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.status, json.loads(resp.read().decode('utf-8'))


def send_recovery_email(cfg, to_email, code):
    host = cfg.get('SMTP_HOST', '').strip()
    user = cfg.get('SMTP_USER', '').strip()
    pw = cfg.get('SMTP_PASS', '').strip()
    port = int(cfg.get('SMTP_PORT') or 587)
    if not (host and user and pw):
        return False
    msg = EmailMessage()
    msg['Subject'] = f'Código de recuperación VentaFlow POS: {code}'
    msg['From'] = user
    msg['To'] = to_email
    msg.set_content(
        f'Hola,\n\nTu código para restablecer tu contraseña en VentaFlow POS es: {code}\n'
        f'Este código vence en 15 minutos.\n\nEquipo VentaFlow POS'
    )
    with smtplib.SMTP(host, port, timeout=10) as server:
        server.starttls()
        server.login(user, pw)
        server.send_message(msg)
    return True


def activate_user_subscription(conn, user_id, payment_id, amount, raw_data, days=SUBSCRIPTION_DAYS):
    user = conn.execute('SELECT id, subscription_status, subscription_expires_at, is_trial FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        return False

    if payment_id:
        already = conn.execute('SELECT id FROM subscription_payments WHERE mp_payment_id = ?', (str(payment_id),)).fetchone()
        if already:
            return True

    now = utc_now()
    base_date = now
    if user['subscription_status'] == 'active' and user['subscription_expires_at'] and not user['is_trial']:
        try:
            current_exp = datetime.fromisoformat(user['subscription_expires_at'])
            if current_exp.tzinfo is None:
                current_exp = current_exp.replace(tzinfo=timezone.utc)
            if current_exp > now:
                base_date = current_exp
        except Exception:
            pass

    new_exp = (base_date + timedelta(days=days)).isoformat()

    conn.execute(
        '''UPDATE users
           SET subscription_status = 'active',
               is_trial = 0,
               subscription_expires_at = ?,
               mp_last_payment_id = ?
           WHERE id = ?''',
        (new_exp, str(payment_id or ''), user_id)
    )
    conn.execute(
        '''INSERT OR IGNORE INTO subscription_payments (user_id, mp_payment_id, amount, status, raw_json, created_at)
           VALUES (?, ?, ?, 'approved', ?, ?)''',
        (user_id, str(payment_id or f'manual_{secrets.token_hex(6)}'), float(amount), json.dumps(raw_data), now.isoformat())
    )
    conn.commit()
    return True


def compute_subscription_info(user_row):
    status = user_row['subscription_status']
    exp_str = user_row['subscription_expires_at']
    is_trial = bool(user_row['is_trial']) if 'is_trial' in user_row.keys() else False
    days_left = 0
    if status == 'active' and exp_str:
        try:
            exp_dt = datetime.fromisoformat(exp_str)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            delta = (exp_dt - utc_now()).total_seconds()
            if delta <= 0:
                status = 'expired'
                days_left = 0
            else:
                days_left = max(1, int(delta // 86400) + (1 if delta % 86400 > 0 else 0))
        except Exception:
            pass
    if user_row['role'] == 'admin':
        status = 'active'
        days_left = 999
        is_trial = False
    return status, days_left, exp_str, is_trial


def start_keepalive_daemon():
    def _loop():
        while True:
            time.sleep(540)  # cada 9 minutos
            try:
                cfg = load_config()
                base = (cfg.get('PUBLIC_BASE_URL') or os.environ.get('RENDER_EXTERNAL_URL') or '').rstrip('/')
                if base.startswith('https://'):
                    req = urllib.request.Request(f"{base}/api/health", headers={'User-Agent': 'VentaFlow-KeepAlive/1.0'})
                    with urllib.request.urlopen(req, timeout=10) as _:
                        pass
            except Exception:
                pass

    t = threading.Thread(target=_loop, daemon=True)
    t.start()


class SaaSHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def send_json(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json_body(self):
        length = int(self.headers.get('Content-Length', 0) or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode('utf-8')
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def get_base_url(self, conn=None):
        cfg = load_config(conn)
        if cfg.get('PUBLIC_BASE_URL'):
            return cfg['PUBLIC_BASE_URL'].rstrip('/')
        host = self.headers.get('Host') or f'localhost:{PORT}'
        proto = self.headers.get('X-Forwarded-Proto', 'http')
        return f"{proto}://{host}"

    def get_session_context(self, conn):
        auth = self.headers.get('Authorization', '')
        token = auth[7:].strip() if auth.startswith('Bearer ') else ''
        if not token:
            return None, None
        row = conn.execute(
            '''SELECT u.*, s.scope AS session_scope
               FROM sessions s
               JOIN users u ON u.id = s.user_id
               WHERE s.token = ?''',
            (token,)
        ).fetchone()
        if not row:
            return None, None
        scope = row['session_scope'] if 'session_scope' in row.keys() and row['session_scope'] else 'owner'
        return row, scope

    def get_current_user(self, conn):
        user, _ = self.get_session_context(conn)
        return user

    def require_active_user(self, conn, owner_only=False):
        user, scope = self.get_session_context(conn)
        if not user:
            self.send_json(401, {'error': 'Sesión expirada o no iniciada.'})
            return None, None
        if owner_only and scope == 'staff' and user['role'] != 'admin':
            self.send_json(403, {'error': 'Acción exclusiva para el titular del comercio (Modo Empleado activo).'})
            return None, None
        status, _, _, _ = compute_subscription_info(user)
        if status != 'active':
            self.send_json(402, {'error': 'Tu periodo activo finalizó. Abona $10.000 por 3 meses para continuar.'})
            return None, None
        return user, scope

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == '/api/health':
            conn = get_db()
            try:
                cfg = load_config(conn)
                trial_days = int(cfg.get('TRIAL_DAYS') or DEFAULT_TRIAL_DAYS)
                self.send_json(200, {
                    'ok': True,
                    'database': 'postgresql' if IS_POSTGRES else 'sqlite',
                    'mp_platform_configured': bool(cfg.get('PLATFORM_MP_ACCESS_TOKEN') or cfg.get('PLATFORM_MP_PAY_LINK')),
                    'smtp_configured': bool(cfg.get('SMTP_HOST') and cfg.get('SMTP_USER')),
                    'subscription_price': SUBSCRIPTION_PRICE,
                    'subscription_days': SUBSCRIPTION_DAYS,
                    'trial_days': trial_days
                })
            finally:
                conn.close()
            return

        if path == '/api/auth/me':
            conn = get_db()
            try:
                user, scope = self.get_session_context(conn)
                if not user:
                    self.send_json(401, {'error': 'No autenticado'})
                    return
                status, days_left, exp_str, is_trial = compute_subscription_info(user)
                self.send_json(200, {
                    'user': {
                        'id': user['id'],
                        'email': user['email'],
                        'role': user['role'],
                        'scope': scope,
                        'store_name': user['store_name'],
                        'subscription_status': status,
                        'is_trial': is_trial,
                        'days_left': days_left,
                        'subscription_expires_at': exp_str,
                        'has_recovery_pin': bool(user['recovery_pin_hash'])
                    }
                })
            finally:
                conn.close()
            return

        if path == '/api/subscription/callback':
            query = parse_qs(parsed.query)
            payment_id = query.get('payment_id', [None])[0] or query.get('collection_id', [None])[0]
            ext_ref = query.get('external_reference', [''])[0]
            conn = get_db()
            try:
                cfg = load_config(conn)
                token = cfg.get('PLATFORM_MP_ACCESS_TOKEN', '')
                activated = False
                if payment_id and token and payment_id != 'null':
                    try:
                        code, pdata = mp_api_request('GET', f'/v1/payments/{payment_id}', token)
                        if code == 200 and pdata.get('status') == 'approved':
                            ref = pdata.get('external_reference') or ext_ref
                            if ref.startswith('sub_user_') and float(pdata.get('transaction_amount', 0)) >= SUBSCRIPTION_PRICE:
                                uid = int(ref.replace('sub_user_', ''))
                                activated = activate_user_subscription(conn, uid, payment_id, pdata.get('transaction_amount', SUBSCRIPTION_PRICE), pdata)
                    except Exception as e:
                        print("Callback verification error:", e)
            finally:
                conn.close()

            target = '/?sub=activated' if activated else '/?sub=pending'
            self.send_response(302)
            self.send_header('Location', target)
            self.end_headers()
            return

        if path == '/api/store/bootstrap':
            conn = get_db()
            try:
                user, scope = self.require_active_user(conn)
                if not user:
                    return
                profile = conn.execute('SELECT * FROM store_profiles WHERE user_id = ?', (user['id'],)).fetchone()
                products = conn.execute('SELECT * FROM products WHERE user_id = ? ORDER BY created_at DESC', (user['id'],)).fetchall()
                customers = conn.execute('SELECT * FROM customers WHERE user_id = ? ORDER BY created_at DESC', (user['id'],)).fetchall()
                orders = conn.execute('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 300', (user['id'],)).fetchall()
                expenses = conn.execute('SELECT * FROM expenses WHERE user_id = ? ORDER BY expense_date DESC, created_at DESC LIMIT 300', (user['id'],)).fetchall()

                prof_dict = dict(profile) if profile else {}
                prods_list = [dict(p) for p in products]
                orders_list = [dict(o) for o in orders]
                expenses_list = [dict(e) for e in expenses]

                if scope == 'staff' and user['role'] != 'admin':
                    prof_dict['mp_access_token'] = ''
                    prof_dict['staff_pin'] = ''
                    for p in prods_list:
                        p['cost_price'] = 0
                    for o in orders_list:
                        o['total_cost'] = 0
                        o['net_profit'] = 0
                    expenses_list = []

                self.send_json(200, {
                    'scope': scope,
                    'profile': prof_dict,
                    'products': prods_list,
                    'customers': [dict(c) for c in customers],
                    'orders': orders_list,
                    'expenses': expenses_list
                })
            finally:
                conn.close()
            return

        if path.startswith('/api/orders/') and path.endswith('/check-payment'):
            order_id = path.split('/')[3]
            conn = get_db()
            try:
                user, _ = self.require_active_user(conn)
                if not user:
                    return
                order = conn.execute('SELECT * FROM orders WHERE id = ? AND user_id = ?', (order_id, user['id'])).fetchone()
                if not order:
                    self.send_json(404, {'error': 'Pedido no encontrado'})
                    return
                if order['payment_status'] == 'paid':
                    self.send_json(200, {'paid': True, 'order': dict(order)})
                    return
                profile = conn.execute('SELECT mp_access_token FROM store_profiles WHERE user_id = ?', (user['id'],)).fetchone()
                mp_token = profile['mp_access_token'] if profile else ''
                if not mp_token:
                    self.send_json(400, {'error': 'Configura tu Access Token de Mercado Pago en Mi Tienda.'})
                    return

                try:
                    _, res = mp_api_request('GET', f'/v1/payments/search?external_reference=order_{order_id}&status=approved', mp_token)
                    results = res.get('results', [])
                    if results:
                        p = results[0]
                        conn.execute(
                            "UPDATE orders SET payment_status = 'paid', mp_payment_id = ? WHERE id = ?",
                            (str(p.get('id', '')), order_id)
                        )
                        conn.commit()
                        updated = conn.execute('SELECT * FROM orders WHERE id = ?', (order_id,)).fetchone()
                        self.send_json(200, {'paid': True, 'order': dict(updated), 'payment': p})
                        return
                except Exception as e:
                    self.send_json(502, {'error': f'Error consultando Mercado Pago: {str(e)}'})
                    return

                self.send_json(200, {'paid': False, 'order': dict(order)})
            finally:
                conn.close()
            return

        if path == '/api/mp/check-payments':
            conn = get_db()
            try:
                user, _ = self.require_active_user(conn)
                if not user:
                    return
                profile = conn.execute('SELECT mp_access_token FROM store_profiles WHERE user_id = ?', (user['id'],)).fetchone()
                query = parse_qs(parsed.query)
                token = query.get('token', [None])[0] or (profile['mp_access_token'] if profile else '')
                if not token:
                    self.send_json(400, {'error': 'Token de Mercado Pago requerido'})
                    return
                try:
                    _, data = mp_api_request('GET', '/v1/payments/search?sort=date_created&criteria=desc&limit=10&status=approved', token)
                    self.send_json(200, data)
                except urllib.error.HTTPError as e:
                    self.send_json(e.code, {'error': e.read().decode('utf-8', errors='ignore')})
                except Exception as e:
                    self.send_json(500, {'error': str(e)})
            finally:
                conn.close()
            return

        if path.startswith('/api/public/track/'):
            tracking_code = path.split('/')[-1].strip().upper()
            conn = get_db()
            try:
                order = conn.execute('SELECT * FROM orders WHERE tracking_code = ?', (tracking_code,)).fetchone()
                if not order:
                    self.send_json(404, {'error': 'Pedido no encontrado'})
                    return
                profile = conn.execute(
                    'SELECT name, slug, store_icon, logo_data_url, phone, address, instagram, currency_symbol FROM store_profiles WHERE user_id = ?',
                    (order['user_id'],)
                ).fetchone()
                self.send_json(200, {
                    'order': {
                        'tracking_code': order['tracking_code'],
                        'folio_number': order['folio_number'],
                        'customer_name': order['customer_name'],
                        'customer_address': order['customer_address'],
                        'items': json.loads(order['items_json']),
                        'subtotal': order['subtotal'],
                        'discount_amount': order['discount_amount'],
                        'discount_label': order['discount_label'],
                        'total': order['total'],
                        'payment_status': order['payment_status'],
                        'mp_payment_link': order['mp_payment_link'],
                        'dispatch_status': order['dispatch_status'],
                        'shipping_carrier': order['shipping_carrier'],
                        'shipping_tracking': order['shipping_tracking'],
                        'notes': order['notes'],
                        'created_at': order['created_at']
                    },
                    'store': dict(profile) if profile else {}
                })
            finally:
                conn.close()
            return

        if path.startswith('/api/public/store/'):
            slug = path.split('/')[4].strip().lower()
            conn = get_db()
            try:
                profile = conn.execute('SELECT * FROM store_profiles WHERE lower(slug) = ?', (slug,)).fetchone()
                if not profile:
                    self.send_json(404, {'error': 'Tienda no encontrada'})
                    return
                owner = conn.execute('SELECT * FROM users WHERE id = ?', (profile['user_id'],)).fetchone()
                if not owner:
                    self.send_json(404, {'error': 'Tienda no disponible'})
                    return
                status, _, _, _ = compute_subscription_info(owner)
                if status != 'active':
                    self.send_json(403, {'error': 'Este catálogo no se encuentra activo temporalmente.'})
                    return

                products = conn.execute(
                    'SELECT id, name, price, category, stock, image_url, variants_json FROM products WHERE user_id = ? ORDER BY category ASC, name ASC',
                    (owner['id'],)
                ).fetchall()
                pub_prods = []
                for p in products:
                    pd = dict(p)
                    try:
                        pd['variants'] = json.loads(pd.get('variants_json') or '[]')
                    except Exception:
                        pd['variants'] = []
                    del pd['variants_json']
                    pub_prods.append(pd)

                self.send_json(200, {
                    'store': {
                        'name': profile['name'],
                        'slug': profile['slug'],
                        'store_icon': profile['store_icon'],
                        'logo_data_url': profile['logo_data_url'],
                        'app_palette': profile['app_palette'],
                        'custom_color': profile['custom_color'],
                        'phone': profile['phone'],
                        'address': profile['address'],
                        'instagram': profile['instagram'],
                        'currency_symbol': profile['currency_symbol'] or '$',
                        'mp_enabled': bool(profile['mp_access_token'])
                    },
                    'products': pub_prods
                })
            finally:
                conn.close()
            return

        if path == '/api/admin/overview':
            conn = get_db()
            try:
                user = self.get_current_user(conn)
                if not user or user['role'] != 'admin':
                    self.send_json(403, {'error': 'Acceso solo para administrador'})
                    return
                users = conn.execute(
                    '''SELECT u.id, u.email, u.role, u.store_name, u.subscription_status,
                              u.subscription_expires_at, u.is_trial, u.mp_last_payment_id, u.created_at,
                              sp.phone AS store_phone, sp.slug AS store_slug
                       FROM users u
                       LEFT JOIN store_profiles sp ON sp.user_id = u.id
                       ORDER BY u.id DESC'''
                ).fetchall()
                enriched_users = []
                for u in users:
                    ud = dict(u)
                    st, dleft, exp_s, is_tr = compute_subscription_info(u)
                    ud['computed_status'] = 'trial' if (st == 'active' and is_tr) else st
                    ud['days_left'] = dleft
                    enriched_users.append(ud)

                payments = conn.execute(
                    '''SELECT sp.*, u.email, u.store_name
                       FROM subscription_payments sp
                       JOIN users u ON u.id = sp.user_id
                       ORDER BY sp.id DESC LIMIT 50'''
                ).fetchall()
                cfg = load_config(conn)
                self.send_json(200, {
                    'users': enriched_users,
                    'payments': [dict(p) for p in payments],
                    'config': {
                        'mp_platform_configured': bool(cfg.get('PLATFORM_MP_ACCESS_TOKEN')),
                        'mp_token_masked': (cfg['PLATFORM_MP_ACCESS_TOKEN'][:12] + '...') if cfg.get('PLATFORM_MP_ACCESS_TOKEN') else '',
                        'platform_mp_pay_link': cfg.get('PLATFORM_MP_PAY_LINK', ''),
                        'public_base_url': cfg.get('PUBLIC_BASE_URL', ''),
                        'trial_days': int(cfg.get('TRIAL_DAYS') or DEFAULT_TRIAL_DAYS),
                        'smtp_host': cfg.get('SMTP_HOST', ''),
                        'smtp_user': cfg.get('SMTP_USER', '')
                    }
                })
            finally:
                conn.close()
            return

        # Serve clean frontend routes
        if path == '/' or path == '':
            self.path = '/index.html'
        elif path == '/seguimiento':
            self.path = '/seguimiento.html'
        elif path == '/tienda' or path.startswith('/tienda/'):
            self.path = '/tienda.html'
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        body = self.read_json_body()

        if path == '/api/auth/register':
            email = (body.get('email') or '').strip().lower()
            password = body.get('password') or ''
            store_name = (body.get('store_name') or '').strip()
            recovery_pin = str(body.get('recovery_pin') or '').strip()

            if not email or '@' not in email or len(password) < 4 or not store_name:
                self.send_json(400, {'error': 'Completa correo válido, nombre de tienda y contraseña (mín. 4 caracteres).'})
                return
            if len(recovery_pin) < 4:
                self.send_json(400, {'error': 'Elige un PIN Secreto de Recuperación de al menos 4 dígitos para poder recuperar tu clave sin depender de soporte.'})
                return

            conn = get_db()
            try:
                exists = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
                if exists:
                    self.send_json(409, {'error': 'Ese correo ya está registrado. Inicia sesión o recupera tu contraseña.'})
                    return

                cfg = load_config(conn)
                trial_days = max(0, int(cfg.get('TRIAL_DAYS') or DEFAULT_TRIAL_DAYS))
                now = utc_now()
                now_iso = now.isoformat()
                sub_status = 'active' if trial_days > 0 else 'pending'
                sub_exp = (now + timedelta(days=trial_days)).isoformat() if trial_days > 0 else None
                is_trial = 1 if trial_days > 0 else 0

                cur = conn.execute(
                    '''INSERT INTO users (email, password_hash, recovery_pin_hash, role, store_name, subscription_status, subscription_expires_at, is_trial, created_at)
                       VALUES (?, ?, ?, 'merchant', ?, ?, ?, ?, ?)''',
                    (email, hash_password(password), hash_password(recovery_pin), store_name, sub_status, sub_exp, is_trial, now_iso)
                )
                uid = cur.lastrowid
                slug = ensure_unique_slug(conn, store_name, uid)
                conn.execute('INSERT INTO store_profiles (user_id, name, slug) VALUES (?, ?, ?)', (uid, store_name, slug))

                sess_token = secrets.token_urlsafe(32)
                exp_iso = (now + timedelta(days=30)).isoformat()
                conn.execute(
                    'INSERT INTO sessions (token, user_id, scope, created_at, expires_at) VALUES (?, ?, ?, ?, ?)',
                    (sess_token, uid, 'owner', now_iso, exp_iso)
                )
                conn.commit()
                self.send_json(201, {
                    'token': sess_token,
                    'user': {
                        'id': uid,
                        'email': email,
                        'role': 'merchant',
                        'scope': 'owner',
                        'store_name': store_name,
                        'subscription_status': sub_status,
                        'is_trial': bool(is_trial),
                        'days_left': trial_days,
                        'subscription_expires_at': sub_exp,
                        'has_recovery_pin': True
                    }
                })
            finally:
                conn.close()
            return

        if path == '/api/auth/login':
            email = (body.get('email') or '').strip().lower()
            password = body.get('password') or ''
            conn = get_db()
            try:
                user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
                if not user or not verify_password(password, user['password_hash']):
                    self.send_json(401, {'error': 'Correo o contraseña incorrectos.'})
                    return
                sess_token = secrets.token_urlsafe(32)
                now_iso = utc_now().isoformat()
                exp_iso = (utc_now() + timedelta(days=30)).isoformat()
                conn.execute(
                    'INSERT INTO sessions (token, user_id, scope, created_at, expires_at) VALUES (?, ?, ?, ?, ?)',
                    (sess_token, user['id'], 'owner', now_iso, exp_iso)
                )
                conn.commit()
                status, days_left, exp_str, is_trial = compute_subscription_info(user)
                self.send_json(200, {
                    'token': sess_token,
                    'user': {
                        'id': user['id'],
                        'email': user['email'],
                        'role': user['role'],
                        'scope': 'owner',
                        'store_name': user['store_name'],
                        'subscription_status': status,
                        'is_trial': is_trial,
                        'days_left': days_left,
                        'subscription_expires_at': exp_str,
                        'has_recovery_pin': bool(user['recovery_pin_hash'])
                    }
                })
            finally:
                conn.close()
            return

        if path == '/api/auth/staff-login':
            identifier = (body.get('identifier') or '').strip().lower()
            pin = str(body.get('staff_pin') or '').strip()
            if not identifier or not pin:
                self.send_json(400, {'error': 'Ingresa el correo o link de la tienda y el PIN de Empleado.'})
                return
            conn = get_db()
            try:
                row = conn.execute(
                    '''SELECT u.*, sp.staff_pin
                       FROM users u
                       JOIN store_profiles sp ON sp.user_id = u.id
                       WHERE lower(u.email) = ? OR lower(sp.slug) = ?''',
                    (identifier, identifier)
                ).fetchone()
                if not row or not row['staff_pin'] or not secrets.compare_digest(str(row['staff_pin']), pin):
                    self.send_json(401, {'error': 'Tienda o PIN de Empleado incorrecto.'})
                    return
                status, days_left, exp_str, is_trial = compute_subscription_info(row)
                if status != 'active':
                    self.send_json(402, {'error': 'La suscripción de esta tienda no está activa.'})
                    return
                sess_token = secrets.token_urlsafe(32)
                now_iso = utc_now().isoformat()
                exp_iso = (utc_now() + timedelta(days=7)).isoformat()
                conn.execute(
                    'INSERT INTO sessions (token, user_id, scope, created_at, expires_at) VALUES (?, ?, ?, ?, ?)',
                    (sess_token, row['id'], 'staff', now_iso, exp_iso)
                )
                conn.commit()
                self.send_json(200, {
                    'token': sess_token,
                    'user': {
                        'id': row['id'],
                        'email': row['email'],
                        'role': 'merchant',
                        'scope': 'staff',
                        'store_name': row['store_name'],
                        'subscription_status': status,
                        'is_trial': is_trial,
                        'days_left': days_left,
                        'subscription_expires_at': exp_str,
                        'has_recovery_pin': True
                    }
                })
            finally:
                conn.close()
            return

        if path == '/api/auth/request-email-code':
            email = (body.get('email') or '').strip().lower()
            conn = get_db()
            try:
                user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
                cfg = load_config(conn)
                if not (cfg.get('SMTP_HOST') and cfg.get('SMTP_USER')):
                    self.send_json(400, {'error': 'Usa tu PIN Secreto de Recuperación para restablecer tu contraseña al instante.'})
                    return
                if user:
                    code = str(secrets.randbelow(900000) + 100000)
                    exp_iso = (utc_now() + timedelta(minutes=15)).isoformat()
                    conn.execute(
                        '''INSERT INTO password_resets (email, code_hash, expires_at) VALUES (?, ?, ?)
                           ON CONFLICT(email) DO UPDATE SET code_hash = excluded.code_hash, expires_at = excluded.expires_at''',
                        (email, hash_password(code), exp_iso)
                    )
                    conn.commit()
                    send_recovery_email(cfg, email, code)
                self.send_json(200, {'ok': True, 'message': 'Si el correo está registrado, enviamos un código de 6 dígitos.'})
            except Exception as e:
                self.send_json(500, {'error': f'No se pudo enviar el correo: {str(e)}'})
            finally:
                conn.close()
            return

        if path == '/api/auth/self-reset-password':
            email = (body.get('email') or '').strip().lower()
            recovery_pin = str(body.get('recovery_pin') or '').strip()
            email_code = str(body.get('email_code') or '').strip()
            new_password = body.get('new_password') or ''

            if not email or len(new_password) < 4:
                self.send_json(400, {'error': 'Ingresa tu correo y una nueva contraseña de al menos 4 caracteres.'})
                return

            conn = get_db()
            try:
                user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
                if not user:
                    self.send_json(404, {'error': 'No encontramos una cuenta con ese correo.'})
                    return

                verified = False
                if recovery_pin and user['recovery_pin_hash'] and verify_password(recovery_pin, user['recovery_pin_hash']):
                    verified = True
                elif email_code:
                    pr = conn.execute('SELECT * FROM password_resets WHERE email = ?', (email,)).fetchone()
                    if pr and verify_password(email_code, pr['code_hash']):
                        exp_dt = datetime.fromisoformat(pr['expires_at'])
                        if exp_dt.tzinfo is None:
                            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                        if exp_dt > utc_now():
                            verified = True
                            conn.execute('DELETE FROM password_resets WHERE email = ?', (email,))

                if not verified:
                    if not user['recovery_pin_hash']:
                        self.send_json(400, {'error': 'Esta cuenta aún no tenía PIN Secreto configurado.'})
                    else:
                        self.send_json(401, {'error': 'PIN Secreto de Recuperación incorrecto.'})
                    return

                conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hash_password(new_password), user['id']))
                conn.execute('DELETE FROM sessions WHERE user_id = ?', (user['id'],))

                sess_token = secrets.token_urlsafe(32)
                now_iso = utc_now().isoformat()
                exp_iso = (utc_now() + timedelta(days=30)).isoformat()
                conn.execute(
                    'INSERT INTO sessions (token, user_id, scope, created_at, expires_at) VALUES (?, ?, ?, ?, ?)',
                    (sess_token, user['id'], 'owner', now_iso, exp_iso)
                )
                conn.commit()
                status, days_left, exp_str, is_trial = compute_subscription_info(user)
                self.send_json(200, {
                    'ok': True,
                    'token': sess_token,
                    'user': {
                        'id': user['id'],
                        'email': user['email'],
                        'role': user['role'],
                        'scope': 'owner',
                        'store_name': user['store_name'],
                        'subscription_status': status,
                        'is_trial': is_trial,
                        'days_left': days_left,
                        'subscription_expires_at': exp_str,
                        'has_recovery_pin': bool(user['recovery_pin_hash'])
                    }
                })
            finally:
                conn.close()
            return

        if path == '/api/auth/change-password':
            conn = get_db()
            try:
                user, scope = self.get_session_context(conn)
                if not user:
                    self.send_json(401, {'error': 'No autenticado'})
                    return
                if scope == 'staff':
                    self.send_json(403, {'error': 'No permitido en Modo Empleado.'})
                    return

                curr_pw = body.get('current_password') or ''
                new_pw = body.get('new_password') or ''
                new_pin = str(body.get('recovery_pin') or '').strip()

                if not verify_password(curr_pw, user['password_hash']):
                    self.send_json(401, {'error': 'Tu contraseña actual es incorrecta.'})
                    return
                if new_pw and len(new_pw) < 4:
                    self.send_json(400, {'error': 'La nueva contraseña debe tener al menos 4 caracteres.'})
                    return
                if new_pin and len(new_pin) < 4:
                    self.send_json(400, {'error': 'El PIN de recuperación debe tener al menos 4 dígitos.'})
                    return

                if new_pw:
                    conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hash_password(new_pw), user['id']))
                if new_pin:
                    conn.execute('UPDATE users SET recovery_pin_hash = ? WHERE id = ?', (hash_password(new_pin), user['id']))
                conn.commit()
                self.send_json(200, {'ok': True})
            finally:
                conn.close()
            return

        if path == '/api/auth/logout':
            auth = self.headers.get('Authorization', '')
            if auth.startswith('Bearer '):
                token = auth[7:].strip()
                conn = get_db()
                try:
                    conn.execute('DELETE FROM sessions WHERE token = ?', (token,))
                    conn.commit()
                finally:
                    conn.close()
            self.send_json(200, {'ok': True})
            return

        if path == '/api/subscription/create-checkout':
            conn = get_db()
            try:
                user = self.get_current_user(conn)
                if not user:
                    self.send_json(401, {'error': 'Debes iniciar sesión primero.'})
                    return
                cfg = load_config(conn)
                mp_token = cfg.get('PLATFORM_MP_ACCESS_TOKEN', '')
                mp_pay_link = cfg.get('PLATFORM_MP_PAY_LINK', '')
                if not mp_token:
                    if mp_pay_link:
                        self.send_json(200, {'init_point': mp_pay_link, 'mode': 'direct_link'})
                        return
                    self.send_json(400, {
                        'error': 'Configura tu Access Token (APP_USR-...) o tu Link de Pago de $10.000 en el Panel Admin para activar el botón de Mercado Pago.',
                        'demo_available': True
                    })
                    return

                base_url = self.get_base_url(conn)
                pref_payload = {
                    "items": [
                        {
                            "id": f"sub_trimestral_{user['id']}",
                            "title": "Suscripción Trimestral (3 Meses) - VentaFlow POS",
                            "description": f"Acceso completo por 90 días para {user['store_name']}",
                            "quantity": 1,
                            "currency_id": "ARS",
                            "unit_price": SUBSCRIPTION_PRICE
                        }
                    ],
                    "payer": {"email": user['email']},
                    "external_reference": f"sub_user_{user['id']}",
                    "back_urls": {
                        "success": f"{base_url}/api/subscription/callback",
                        "failure": f"{base_url}/?sub=failed",
                        "pending": f"{base_url}/api/subscription/callback"
                    },
                    "auto_return": "approved"
                }
                if base_url.startswith('https://'):
                    pref_payload["notification_url"] = f"{base_url}/api/webhooks/mp-subscription"

                try:
                    _, pref = mp_api_request('POST', '/checkout/preferences', mp_token, pref_payload)
                    self.send_json(200, {
                        'init_point': pref.get('init_point'),
                        'sandbox_init_point': pref.get('sandbox_init_point'),
                        'preference_id': pref.get('id')
                    })
                except urllib.error.HTTPError as e:
                    err = e.read().decode('utf-8', errors='ignore')
                    self.send_json(502, {'error': f'Error Mercado Pago: {err}'})
                except Exception as e:
                    self.send_json(500, {'error': str(e)})
            finally:
                conn.close()
            return

        if path == '/api/subscription/simulate-pay':
            conn = get_db()
            try:
                user = self.get_current_user(conn)
                if not user:
                    self.send_json(401, {'error': 'No autenticado'})
                    return
                cfg = load_config(conn)
                if cfg.get('PLATFORM_MP_ACCESS_TOKEN') and user['role'] != 'admin':
                    self.send_json(403, {'error': 'Simulación deshabilitada cuando hay token real configurado.'})
                    return
                pid = f"demo_{secrets.token_hex(5)}"
                activate_user_subscription(conn, user['id'], pid, SUBSCRIPTION_PRICE, {'demo': True})
                updated = conn.execute('SELECT * FROM users WHERE id = ?', (user['id'],)).fetchone()
                status, days_left, exp_str, is_trial = compute_subscription_info(updated)
                self.send_json(200, {
                    'ok': True,
                    'subscription_status': status,
                    'is_trial': is_trial,
                    'days_left': days_left,
                    'subscription_expires_at': exp_str
                })
            finally:
                conn.close()
            return

        if path == '/api/webhooks/mp-subscription':
            query = parse_qs(parsed.query)
            topic = query.get('topic', [None])[0] or body.get('type') or body.get('topic')
            payment_id = (
                query.get('id', [None])[0]
                or query.get('data.id', [None])[0]
                or (body.get('data') or {}).get('id')
            )
            conn = get_db()
            try:
                cfg = load_config(conn)
                mp_token = cfg.get('PLATFORM_MP_ACCESS_TOKEN', '')
                if mp_token and payment_id and topic in ('payment', 'payment.created', 'payment.updated', None):
                    try:
                        code, pdata = mp_api_request('GET', f'/v1/payments/{payment_id}', mp_token)
                        if code == 200 and pdata.get('status') == 'approved':
                            ref = pdata.get('external_reference', '')
                            if ref.startswith('sub_user_') and float(pdata.get('transaction_amount', 0)) >= SUBSCRIPTION_PRICE:
                                uid = int(ref.replace('sub_user_', ''))
                                activate_user_subscription(conn, uid, payment_id, pdata.get('transaction_amount', SUBSCRIPTION_PRICE), pdata)
                    except Exception as e:
                        print("Webhook MP error:", e)
            finally:
                conn.close()
            self.send_json(200, {'received': True})
            return

        if path == '/api/products':
            conn = get_db()
            try:
                user, _ = self.require_active_user(conn, owner_only=True)
                if not user:
                    return
                pid = 'prod_' + secrets.token_hex(6)
                now_iso = utc_now().isoformat()
                variants = body.get('variants') if isinstance(body.get('variants'), list) else []
                stock_val = int(body.get('stock') or 0)
                if variants:
                    stock_val = sum(max(0, int(v.get('stock') or 0)) for v in variants)
                conn.execute(
                    '''INSERT INTO products (id, user_id, name, price, cost_price, category, stock, min_stock, barcode, sku, image_url, variants_json, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (
                        pid, user['id'],
                        (body.get('name') or '').strip(),
                        float(body.get('price') or 0),
                        float(body.get('cost_price') or 0),
                        (body.get('category') or 'General').strip(),
                        stock_val,
                        int(body.get('min_stock') or 3),
                        (body.get('barcode') or '').strip(),
                        (body.get('sku') or body.get('barcode') or '').strip(),
                        (body.get('image_url') or '').strip(),
                        json.dumps(variants, ensure_ascii=False),
                        now_iso
                    )
                )
                conn.commit()
                prod = conn.execute('SELECT * FROM products WHERE id = ?', (pid,)).fetchone()
                self.send_json(201, {'product': dict(prod)})
            finally:
                conn.close()
            return

        if path == '/api/products/batch-samples':
            conn = get_db()
            try:
                user, _ = self.require_active_user(conn, owner_only=True)
                if not user:
                    return
                samples = [
                    ("Crema Hidratante Facial Glow", 12500, 6800, "Cuidado Facial", 14, 3, "77910001"),
                    ("Set 5 Organizadores de Viaje", 15900, 8500, "Hogar & Viaje", 9, 3, "77910002"),
                    ("Termo Acero Inoxidable 750ml", 18500, 10200, "Bazar", 6, 3, "77910003"),
                    ("Serum Vitamina C 30ml", 11200, 5900, "Cuidado Facial", 2, 3, "77910004"),
                    ("Auriculares Inalámbricos Mini", 24900, 14500, "Tecnología", 0, 2, "77910005"),
                ]
                now_iso = utc_now().isoformat()
                for name, price, cost, cat, st, min_st, bar in samples:
                    pid = 'prod_' + secrets.token_hex(6)
                    conn.execute(
                        '''INSERT INTO products (id, user_id, name, price, cost_price, category, stock, min_stock, barcode, sku, created_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                        (pid, user['id'], name, price, cost, cat, st, min_st, bar, bar, now_iso)
                    )
                conn.commit()
                products = conn.execute('SELECT * FROM products WHERE user_id = ? ORDER BY created_at DESC', (user['id'],)).fetchall()
                self.send_json(201, {'products': [dict(p) for p in products]})
            finally:
                conn.close()
            return

        if path == '/api/expenses':
            conn = get_db()
            try:
                user, _ = self.require_active_user(conn, owner_only=True)
                if not user:
                    return
                desc = (body.get('description') or '').strip()
                amount = float(body.get('amount') or 0)
                if not desc or amount <= 0:
                    self.send_json(400, {'error': 'Ingresa descripción y monto válido del gasto.'})
                    return
                eid = 'exp_' + secrets.token_hex(6)
                now_iso = utc_now().isoformat()
                exp_date = (body.get('expense_date') or now_iso[:10]).strip()
                conn.execute(
                    '''INSERT INTO expenses (id, user_id, category, description, amount, expense_date, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)''',
                    (eid, user['id'], (body.get('category') or 'Operativo').strip(), desc, amount, exp_date, now_iso)
                )
                conn.commit()
                exp_row = conn.execute('SELECT * FROM expenses WHERE id = ?', (eid,)).fetchone()
                self.send_json(201, {'expense': dict(exp_row)})
            finally:
                conn.close()
            return

        if path == '/api/customers':
            conn = get_db()
            try:
                user, _ = self.require_active_user(conn)
                if not user:
                    return
                cid = 'cust_' + secrets.token_hex(6)
                now_iso = utc_now().isoformat()
                conn.execute(
                    '''INSERT INTO customers (id, user_id, name, phone, address, handle, notes, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                    (
                        cid, user['id'],
                        (body.get('name') or '').strip(),
                        (body.get('phone') or '').strip(),
                        (body.get('address') or '').strip(),
                        (body.get('handle') or '').strip(),
                        (body.get('notes') or '').strip(),
                        now_iso
                    )
                )
                conn.commit()
                cust = conn.execute('SELECT * FROM customers WHERE id = ?', (cid,)).fetchone()
                self.send_json(201, {'customer': dict(cust)})
            finally:
                conn.close()
            return

        if path == '/api/orders':
            conn = get_db()
            try:
                user, _ = self.require_active_user(conn)
                if not user:
                    return
                items = body.get('items') or []
                if not items:
                    self.send_json(400, {'error': 'Agrega al menos un producto al pedido.'})
                    return

                profile = conn.execute('SELECT next_folio_number FROM store_profiles WHERE user_id = ?', (user['id'],)).fetchone()
                folio_num = (profile['next_folio_number'] if profile else 1001)
                folio_str = '#' + str(folio_num).zfill(6)
                oid = 'ord_' + secrets.token_hex(6)
                tracking_code = 'PED-' + secrets.token_hex(3).upper()
                now_iso = utc_now().isoformat()

                cname = (body.get('customer_name') or 'Cliente').strip()
                cphone = (body.get('customer_phone') or '').strip()
                caddr = (body.get('customer_address') or '').strip()
                chandle = (body.get('customer_handle') or '').strip()

                total_cost = 0.0
                enriched_items = []
                for item in items:
                    pname = (item.get('productName') or '').strip()
                    base_name = pname.split(' (')[0].strip()
                    variant_sel = (item.get('variantName') or '').strip()
                    qty = int(item.get('quantity') or 1)
                    prod = conn.execute(
                        'SELECT id, stock, cost_price, variants_json FROM products WHERE user_id = ? AND (lower(name) = ? OR lower(name) = ?)',
                        (user['id'], pname.lower(), base_name.lower())
                    ).fetchone()
                    unit_cost = float(prod['cost_price']) if prod else float(item.get('unitCost') or 0)
                    cost_sub = unit_cost * qty
                    total_cost += cost_sub
                    enriched = dict(item)
                    enriched['unitCost'] = unit_cost
                    enriched['costSubtotal'] = cost_sub
                    enriched_items.append(enriched)
                    if prod:
                        new_stock = max(0, int(prod['stock']) - qty)
                        variants_raw = prod['variants_json'] or '[]'
                        try:
                            vlist = json.loads(variants_raw)
                        except Exception:
                            vlist = []
                        if vlist and variant_sel:
                            for v in vlist:
                                if str(v.get('name', '')).lower() == variant_sel.lower():
                                    v['stock'] = max(0, int(v.get('stock') or 0) - qty)
                            new_stock = sum(max(0, int(v.get('stock') or 0)) for v in vlist)
                            conn.execute('UPDATE products SET stock = ?, variants_json = ? WHERE id = ?', (new_stock, json.dumps(vlist, ensure_ascii=False), prod['id']))
                        else:
                            conn.execute('UPDATE products SET stock = ? WHERE id = ?', (new_stock, prod['id']))

                order_total = float(body.get('total') or 0)
                net_profit = order_total - total_cost

                conn.execute(
                    '''INSERT INTO orders (
                           id, user_id, tracking_code, folio_number, customer_name, customer_phone,
                           customer_address, customer_handle, items_json, subtotal, discount_amount,
                           discount_label, total, total_cost, net_profit, payment_status, dispatch_status, notes, source, created_at
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pos', ?)''',
                    (
                        oid, user['id'], tracking_code, folio_str, cname, cphone, caddr, chandle,
                        json.dumps(enriched_items, ensure_ascii=False),
                        float(body.get('subtotal') or 0),
                        float(body.get('discount_amount') or 0),
                        (body.get('discount_label') or ''),
                        order_total,
                        total_cost,
                        net_profit,
                        body.get('payment_status') or 'pending',
                        body.get('dispatch_status') or 'to_prepare',
                        (body.get('notes') or '').strip(),
                        now_iso
                    )
                )

                conn.execute('UPDATE store_profiles SET next_folio_number = ? WHERE user_id = ?', (folio_num + 1, user['id']))

                if cname and cname.lower() != 'cliente' and (cphone or caddr):
                    existing_cust = conn.execute(
                        'SELECT id FROM customers WHERE user_id = ? AND lower(name) = ?',
                        (user['id'], cname.lower())
                    ).fetchone()
                    if existing_cust:
                        conn.execute(
                            'UPDATE customers SET phone = COALESCE(NULLIF(?, ""), phone), address = COALESCE(NULLIF(?, ""), address), handle = COALESCE(NULLIF(?, ""), handle) WHERE id = ?',
                            (cphone, caddr, chandle, existing_cust['id'])
                        )
                    else:
                        conn.execute(
                            'INSERT INTO customers (id, user_id, name, phone, address, handle, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                            ('cust_' + secrets.token_hex(6), user['id'], cname, cphone, caddr, chandle, now_iso)
                        )

                conn.commit()
                order = conn.execute('SELECT * FROM orders WHERE id = ?', (oid,)).fetchone()
                self.send_json(201, {'order': dict(order), 'next_folio_number': folio_num + 1})
            finally:
                conn.close()
            return

        if path.startswith('/api/public/store/') and path.endswith('/checkout'):
            slug = path.split('/')[4].strip().lower()
            conn = get_db()
            try:
                profile = conn.execute('SELECT * FROM store_profiles WHERE lower(slug) = ?', (slug,)).fetchone()
                if not profile:
                    self.send_json(404, {'error': 'Tienda no encontrada'})
                    return
                owner = conn.execute('SELECT * FROM users WHERE id = ?', (profile['user_id'],)).fetchone()
                status, _, _, _ = compute_subscription_info(owner)
                if status != 'active':
                    self.send_json(403, {'error': 'Tienda temporalmente inactiva'})
                    return

                req_items = body.get('items') or []
                cname = (body.get('customer_name') or '').strip()
                cphone = (body.get('customer_phone') or '').strip()
                caddr = (body.get('customer_address') or '').strip()
                notes = (body.get('notes') or '').strip()

                if not cname or not cphone or not req_items:
                    self.send_json(400, {'error': 'Completa tu nombre, WhatsApp y al menos un producto.'})
                    return

                enriched_items = []
                subtotal = 0.0
                total_cost = 0.0

                for ri in req_items:
                    pid = ri.get('product_id')
                    qty = max(1, int(ri.get('quantity') or 1))
                    vname = (ri.get('variant_name') or '').strip()
                    prod = conn.execute('SELECT * FROM products WHERE id = ? AND user_id = ?', (pid, owner['id'])).fetchone()
                    if not prod:
                        continue
                    if int(prod['stock']) < qty:
                        self.send_json(400, {'error': f"Stock insuficiente para {prod['name']} (disponibles: {prod['stock']})."})
                        return

                    uprice = float(prod['price'])
                    ucost = float(prod['cost_price'] or 0)
                    display_name = f"{prod['name']} ({vname})" if vname else prod['name']
                    sub = uprice * qty
                    csub = ucost * qty
                    subtotal += sub
                    total_cost += csub
                    enriched_items.append({
                        'productName': display_name,
                        'variantName': vname,
                        'unitPrice': uprice,
                        'unitCost': ucost,
                        'quantity': qty,
                        'subtotal': sub,
                        'costSubtotal': csub
                    })

                    # Deduct stock
                    try:
                        vlist = json.loads(prod['variants_json'] or '[]')
                    except Exception:
                        vlist = []
                    if vlist and vname:
                        for v in vlist:
                            if str(v.get('name', '')).lower() == vname.lower():
                                if int(v.get('stock') or 0) < qty:
                                    self.send_json(400, {'error': f"Sin stock suficiente de {prod['name']} ({vname})."})
                                    return
                                v['stock'] = max(0, int(v.get('stock') or 0) - qty)
                        new_st = sum(max(0, int(v.get('stock') or 0)) for v in vlist)
                        conn.execute('UPDATE products SET stock = ?, variants_json = ? WHERE id = ?', (new_st, json.dumps(vlist, ensure_ascii=False), prod['id']))
                    else:
                        conn.execute('UPDATE products SET stock = ? WHERE id = ?', (max(0, int(prod['stock']) - qty), prod['id']))

                if not enriched_items:
                    self.send_json(400, {'error': 'Productos inválidos.'})
                    return

                folio_num = int(profile['next_folio_number'] or 1001)
                folio_str = '#' + str(folio_num).zfill(6)
                oid = 'ord_' + secrets.token_hex(6)
                tracking_code = 'PED-' + secrets.token_hex(3).upper()
                now_iso = utc_now().isoformat()
                net_profit = subtotal - total_cost

                mp_link = ''
                mp_token = (profile['mp_access_token'] or '').strip()
                if mp_token:
                    base_url = self.get_base_url(conn)
                    pref_payload = {
                        "items": [{
                            "id": tracking_code,
                            "title": f"Pedido {folio_str} - {profile['name']}",
                            "quantity": 1,
                            "currency_id": "ARS",
                            "unit_price": float(subtotal)
                        }],
                        "external_reference": f"order_{oid}",
                        "back_urls": {
                            "success": f"{base_url}/seguimiento.html?code={tracking_code}",
                            "failure": f"{base_url}/seguimiento.html?code={tracking_code}",
                            "pending": f"{base_url}/seguimiento.html?code={tracking_code}"
                        },
                        "auto_return": "approved"
                    }
                    try:
                        _, pref = mp_api_request('POST', '/checkout/preferences', mp_token, pref_payload)
                        mp_link = pref.get('init_point') or pref.get('sandbox_init_point') or ''
                    except Exception:
                        mp_link = ''

                conn.execute(
                    '''INSERT INTO orders (
                           id, user_id, tracking_code, folio_number, customer_name, customer_phone,
                           customer_address, customer_handle, items_json, subtotal, discount_amount,
                           discount_label, total, total_cost, net_profit, payment_status, mp_payment_link,
                           dispatch_status, notes, source, created_at
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, '', ?, ?, 0, '', ?, ?, ?, 'pending', ?, 'to_prepare', ?, 'web_store', ?)''',
                    (
                        oid, owner['id'], tracking_code, folio_str, cname, cphone, caddr,
                        json.dumps(enriched_items, ensure_ascii=False),
                        subtotal, subtotal, total_cost, net_profit, mp_link, notes, now_iso
                    )
                )
                conn.execute('UPDATE store_profiles SET next_folio_number = ? WHERE user_id = ?', (folio_num + 1, owner['id']))

                existing_cust = conn.execute('SELECT id FROM customers WHERE user_id = ? AND lower(name) = ?', (owner['id'], cname.lower())).fetchone()
                if existing_cust:
                    conn.execute('UPDATE customers SET phone = ?, address = COALESCE(NULLIF(?, ""), address) WHERE id = ?', (cphone, caddr, existing_cust['id']))
                else:
                    conn.execute(
                        'INSERT INTO customers (id, user_id, name, phone, address, handle, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                        ('cust_' + secrets.token_hex(6), owner['id'], cname, cphone, caddr, 'Tienda Web', now_iso)
                    )
                conn.commit()
                self.send_json(201, {
                    'order': {
                        'folio_number': folio_str,
                        'tracking_code': tracking_code,
                        'total': subtotal
                    },
                    'payment_link': mp_link,
                    'tracking_url': f"/seguimiento.html?code={tracking_code}",
                    'store_phone': profile['phone']
                })
            finally:
                conn.close()
            return

        if path.startswith('/api/orders/') and path.endswith('/payment-link'):
            order_id = path.split('/')[3]
            conn = get_db()
            try:
                user, _ = self.require_active_user(conn)
                if not user:
                    return
                order = conn.execute('SELECT * FROM orders WHERE id = ? AND user_id = ?', (order_id, user['id'])).fetchone()
                if not order:
                    self.send_json(404, {'error': 'Pedido no encontrado'})
                    return
                profile = conn.execute('SELECT name, mp_access_token FROM store_profiles WHERE user_id = ?', (user['id'],)).fetchone()
                mp_token = profile['mp_access_token'] if profile else ''
                if not mp_token:
                    self.send_json(400, {'error': 'Configura primero tu Access Token de Mercado Pago en Cobros MP.'})
                    return

                base_url = self.get_base_url(conn)
                pref_payload = {
                    "items": [
                        {
                            "id": order['tracking_code'],
                            "title": f"Pedido {order['folio_number']} - {profile['name']}",
                            "quantity": 1,
                            "currency_id": "ARS",
                            "unit_price": float(order['total'])
                        }
                    ],
                    "external_reference": f"order_{order_id}",
                    "back_urls": {
                        "success": f"{base_url}/seguimiento.html?code={order['tracking_code']}",
                        "failure": f"{base_url}/seguimiento.html?code={order['tracking_code']}",
                        "pending": f"{base_url}/seguimiento.html?code={order['tracking_code']}"
                    },
                    "auto_return": "approved"
                }
                try:
                    _, pref = mp_api_request('POST', '/checkout/preferences', mp_token, pref_payload)
                    link = pref.get('init_point') or pref.get('sandbox_init_point') or ''
                    conn.execute('UPDATE orders SET mp_payment_link = ? WHERE id = ?', (link, order_id))
                    conn.commit()
                    self.send_json(200, {'payment_link': link, 'preference_id': pref.get('id')})
                except urllib.error.HTTPError as e:
                    self.send_json(502, {'error': f'Error Mercado Pago: {e.read().decode("utf-8", errors="ignore")}'})
                except Exception as e:
                    self.send_json(500, {'error': str(e)})
            finally:
                conn.close()
            return

        if path == '/api/admin/activate-user':
            conn = get_db()
            try:
                user = self.get_current_user(conn)
                if not user or user['role'] != 'admin':
                    self.send_json(403, {'error': 'Solo administrador'})
                    return
                target_id = int(body.get('user_id') or 0)
                action = body.get('action') or 'activate'
                if action == 'suspend':
                    conn.execute("UPDATE users SET subscription_status = 'expired' WHERE id = ? AND role != 'admin'", (target_id,))
                    conn.commit()
                else:
                    activate_user_subscription(conn, target_id, f"admin_{secrets.token_hex(4)}", SUBSCRIPTION_PRICE, {'manual_admin': True})
                self.send_json(200, {'ok': True})
            finally:
                conn.close()
            return

        if path == '/api/admin/reset-user-password':
            conn = get_db()
            try:
                user = self.get_current_user(conn)
                if not user or user['role'] != 'admin':
                    self.send_json(403, {'error': 'Solo administrador'})
                    return
                target_id = int(body.get('user_id') or 0)
                new_pw = (body.get('new_password') or '').strip()
                new_pin = (body.get('recovery_pin') or '').strip()
                if len(new_pw) < 4:
                    self.send_json(400, {'error': 'La nueva clave debe tener al menos 4 caracteres.'})
                    return
                if new_pin and len(new_pin) >= 4:
                    conn.execute(
                        "UPDATE users SET password_hash = ?, recovery_pin_hash = ? WHERE id = ? AND role != 'admin'",
                        (hash_password(new_pw), hash_password(new_pin), target_id)
                    )
                else:
                    conn.execute(
                        "UPDATE users SET password_hash = ? WHERE id = ? AND role != 'admin'",
                        (hash_password(new_pw), target_id)
                    )
                conn.execute('DELETE FROM sessions WHERE user_id = ?', (target_id,))
                conn.commit()
                self.send_json(200, {'ok': True})
            finally:
                conn.close()
            return

        if path == '/api/admin/config':
            conn = get_db()
            try:
                user = self.get_current_user(conn)
                if not user or user['role'] != 'admin':
                    self.send_json(403, {'error': 'Solo administrador'})
                    return
                updates = {}
                if 'platform_mp_token' in body and body['platform_mp_token'].strip():
                    updates['PLATFORM_MP_ACCESS_TOKEN'] = body['platform_mp_token'].strip()
                if 'platform_mp_pay_link' in body:
                    updates['PLATFORM_MP_PAY_LINK'] = body['platform_mp_pay_link'].strip()
                if 'public_base_url' in body:
                    updates['PUBLIC_BASE_URL'] = body['public_base_url'].strip()
                if 'trial_days' in body:
                    updates['TRIAL_DAYS'] = str(max(0, int(body['trial_days'] or 0)))
                if 'smtp_host' in body:
                    updates['SMTP_HOST'] = body['smtp_host'].strip()
                if 'smtp_user' in body:
                    updates['SMTP_USER'] = body['smtp_user'].strip()
                if 'smtp_pass' in body and body['smtp_pass'].strip():
                    updates['SMTP_PASS'] = body['smtp_pass'].strip()
                save_config(updates, conn)
                self.send_json(200, {'ok': True})
            finally:
                conn.close()
            return

        self.send_json(404, {'error': 'Ruta no encontrada'})

    def do_PUT(self):
        parsed = urlparse(self.path)
        path = parsed.path
        body = self.read_json_body()

        if path == '/api/store/profile':
            conn = get_db()
            try:
                user, _ = self.require_active_user(conn, owner_only=True)
                if not user:
                    return
                if 'slug' in body and body['slug'].strip():
                    body['slug'] = ensure_unique_slug(conn, body['slug'], user['id'])

                fields = [
                    'name', 'slug', 'store_icon', 'logo_data_url', 'receipt_theme', 'app_palette',
                    'custom_color', 'business_mode', 'phone', 'address',
                    'instagram', 'website', 'currency_symbol', 'next_folio_number',
                    'receipt_footer_message', 'mp_access_token', 'staff_pin', 'voice_accent', 'voice_template'
                ]
                set_clauses = []
                values = []
                for f in fields:
                    if f in body:
                        set_clauses.append(f"{f} = ?")
                        values.append(body[f])
                if set_clauses:
                    values.append(user['id'])
                    conn.execute(f"UPDATE store_profiles SET {', '.join(set_clauses)} WHERE user_id = ?", values)
                    if 'name' in body and body['name']:
                        conn.execute('UPDATE users SET store_name = ? WHERE id = ?', (body['name'], user['id']))
                    conn.commit()
                profile = conn.execute('SELECT * FROM store_profiles WHERE user_id = ?', (user['id'],)).fetchone()
                self.send_json(200, {'profile': dict(profile)})
            finally:
                conn.close()
            return

        if path.startswith('/api/products/'):
            pid = path.split('/')[-1]
            conn = get_db()
            try:
                user, _ = self.require_active_user(conn, owner_only=True)
                if not user:
                    return
                variants = body.get('variants') if isinstance(body.get('variants'), list) else None
                stock_val = int(body.get('stock') or 0)
                if variants is not None and len(variants) > 0:
                    stock_val = sum(max(0, int(v.get('stock') or 0)) for v in variants)

                existing = conn.execute('SELECT image_url, variants_json FROM products WHERE id = ? AND user_id = ?', (pid, user['id'])).fetchone()
                if not existing:
                    self.send_json(404, {'error': 'Producto no encontrado'})
                    return

                img_url = body.get('image_url') if 'image_url' in body else existing['image_url']
                var_json = json.dumps(variants, ensure_ascii=False) if variants is not None else existing['variants_json']

                conn.execute(
                    '''UPDATE products
                       SET name = ?, price = ?, cost_price = ?, category = ?, stock = ?, min_stock = ?, barcode = ?, sku = ?, image_url = ?, variants_json = ?
                       WHERE id = ? AND user_id = ?''',
                    (
                        (body.get('name') or '').strip(),
                        float(body.get('price') or 0),
                        float(body.get('cost_price') or 0),
                        (body.get('category') or 'General').strip(),
                        stock_val,
                        int(body.get('min_stock') or 3),
                        (body.get('barcode') or '').strip(),
                        (body.get('barcode') or '').strip(),
                        img_url or '',
                        var_json or '[]',
                        pid, user['id']
                    )
                )
                conn.commit()
                prod = conn.execute('SELECT * FROM products WHERE id = ? AND user_id = ?', (pid, user['id'])).fetchone()
                self.send_json(200, {'product': dict(prod) if prod else None})
            finally:
                conn.close()
            return

        self.send_json(404, {'error': 'Ruta no encontrada'})

    def do_PATCH(self):
        parsed = urlparse(self.path)
        path = parsed.path
        body = self.read_json_body()

        if path.startswith('/api/products/'):
            pid = path.split('/')[-1]
            conn = get_db()
            try:
                user, _ = self.require_active_user(conn)
                if not user:
                    return
                if 'stock_delta' in body:
                    prod = conn.execute('SELECT stock FROM products WHERE id = ? AND user_id = ?', (pid, user['id'])).fetchone()
                    if prod:
                        new_st = max(0, int(prod['stock']) + int(body['stock_delta']))
                        conn.execute('UPDATE products SET stock = ? WHERE id = ? AND user_id = ?', (new_st, pid, user['id']))
                        conn.commit()
                elif 'stock' in body:
                    conn.execute('UPDATE products SET stock = ? WHERE id = ? AND user_id = ?', (max(0, int(body['stock'])), pid, user['id']))
                    conn.commit()
                prod = conn.execute('SELECT * FROM products WHERE id = ? AND user_id = ?', (pid, user['id'])).fetchone()
                self.send_json(200, {'product': dict(prod) if prod else None})
            finally:
                conn.close()
            return

        if path.startswith('/api/orders/'):
            oid = path.split('/')[-1]
            conn = get_db()
            try:
                user, _ = self.require_active_user(conn)
                if not user:
                    return
                allowed = ['payment_status', 'dispatch_status', 'shipping_carrier', 'shipping_tracking', 'notes']
                set_clauses = []
                values = []
                for f in allowed:
                    if f in body:
                        set_clauses.append(f"{f} = ?")
                        values.append(body[f])
                if set_clauses:
                    values.extend([oid, user['id']])
                    conn.execute(f"UPDATE orders SET {', '.join(set_clauses)} WHERE id = ? AND user_id = ?", values)
                    conn.commit()
                order = conn.execute('SELECT * FROM orders WHERE id = ? AND user_id = ?', (oid, user['id'])).fetchone()
                self.send_json(200, {'order': dict(order) if order else None})
            finally:
                conn.close()
            return

        self.send_json(404, {'error': 'Ruta no encontrada'})

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path.startswith('/api/products/'):
            pid = path.split('/')[-1]
            conn = get_db()
            try:
                user, _ = self.require_active_user(conn, owner_only=True)
                if not user:
                    return
                conn.execute('DELETE FROM products WHERE id = ? AND user_id = ?', (pid, user['id']))
                conn.commit()
                self.send_json(200, {'ok': True})
            finally:
                conn.close()
            return

        if path.startswith('/api/expenses/'):
            eid = path.split('/')[-1]
            conn = get_db()
            try:
                user, _ = self.require_active_user(conn, owner_only=True)
                if not user:
                    return
                conn.execute('DELETE FROM expenses WHERE id = ? AND user_id = ?', (eid, user['id']))
                conn.commit()
                self.send_json(200, {'ok': True})
            finally:
                conn.close()
            return

        self.send_json(404, {'error': 'Ruta no encontrada'})


def run():
    init_db()
    start_keepalive_daemon()
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.daemon_threads = True
    with socketserver.ThreadingTCPServer(("", PORT), SaaSHandler) as httpd:
        print("=" * 64)
        print(f"[OK] VENTAFLOW POS SaaS v3.0 ACTIVO en http://localhost:{PORT}")
        print("Motor DB:", "PostgreSQL" if IS_POSTGRES else f"SQLite ({DB_PATH})")
        print("=" * 64)
        httpd.serve_forever()


if __name__ == "__main__":
    run()
