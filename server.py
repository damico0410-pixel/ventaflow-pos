import http.server
import socketserver
import os
import sys
import json
import sqlite3
import hashlib
import secrets
import urllib.request
import urllib.error
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


def utc_now():
    return datetime.now(timezone.utc)


def load_config():
    cfg = {
        "PLATFORM_MP_ACCESS_TOKEN": os.environ.get("PLATFORM_MP_ACCESS_TOKEN", ""),
        "PLATFORM_MP_PAY_LINK": os.environ.get("PLATFORM_MP_PAY_LINK", ""),
        "PUBLIC_BASE_URL": os.environ.get("PUBLIC_BASE_URL", ""),
        "ADMIN_EMAIL": os.environ.get("ADMIN_EMAIL", "admin@comprobantespos.com"),
        "ADMIN_PASSWORD": os.environ.get("ADMIN_PASSWORD", "admin1234"),
    }
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                saved = json.load(f)
                cfg.update({k: v for k, v in saved.items() if v is not None})
        except Exception as e:
            print("Error reading config.json:", e)
    return cfg


def save_config(new_cfg):
    cfg = load_config()
    cfg.update(new_cfg)
    with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    return cfg


def hash_password(password, salt=None):
    if not salt:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 120000)
    return f"{salt}${dk.hex()}"


def verify_password(password, stored_hash):
    try:
        salt, hex_digest = stored_hash.split('$', 1)
        return secrets.compare_digest(hash_password(password, salt), stored_hash)
    except Exception:
        return False


DATABASE_URL = os.environ.get('DATABASE_URL', '').strip()
IS_POSTGRES = bool(DATABASE_URL)


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


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'merchant',
            store_name TEXT NOT NULL,
            subscription_status TEXT DEFAULT 'pending',
            subscription_expires_at TEXT,
            mp_last_payment_id TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS store_profiles (
            user_id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            store_icon TEXT DEFAULT '🛍️',
            logo_data_url TEXT DEFAULT '',
            receipt_theme TEXT DEFAULT 'coquette',
            app_palette TEXT DEFAULT 'violet',
            custom_color TEXT DEFAULT '#7C3AED',
            business_mode TEXT DEFAULT 'Pedidos & Despachos',
            phone TEXT DEFAULT '',
            address TEXT DEFAULT '',
            instagram TEXT DEFAULT '',
            website TEXT DEFAULT '',
            currency_symbol TEXT DEFAULT '$',
            next_folio_number INTEGER DEFAULT 1001,
            receipt_footer_message TEXT DEFAULT '¡Muchas gracias por tu compra! 💖 Preparamos tu pedido con mucho cuidado para despacharlo pronto.',
            mp_access_token TEXT DEFAULT '',
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
    for alter_sql in [
        "ALTER TABLE products ADD COLUMN cost_price REAL DEFAULT 0",
        "ALTER TABLE orders ADD COLUMN total_cost REAL DEFAULT 0",
        "ALTER TABLE orders ADD COLUMN net_profit REAL DEFAULT 0",
        "ALTER TABLE store_profiles ADD COLUMN app_palette TEXT DEFAULT 'violet'",
        "ALTER TABLE store_profiles ADD COLUMN custom_color TEXT DEFAULT '#7C3AED'",
        "ALTER TABLE store_profiles ADD COLUMN business_mode TEXT DEFAULT 'Pedidos & Despachos'",
    ]:
        try:
            c.execute(alter_sql)
            conn.commit()
        except Exception:
            if IS_POSTGRES:
                conn.rollback()

    # Ensure default admin user exists
    cfg = load_config()
    admin_email = cfg['ADMIN_EMAIL'].strip().lower()
    existing = c.execute('SELECT id FROM users WHERE email = ?', (admin_email,)).fetchone()
    if not existing:
        now_iso = utc_now().isoformat()
        exp_iso = (utc_now() + timedelta(days=3650)).isoformat()
        c.execute(
            '''INSERT INTO users (email, password_hash, role, store_name, subscription_status, subscription_expires_at, created_at)
               VALUES (?, ?, 'admin', 'Admin Central POS', 'active', ?, ?)''',
            (admin_email, hash_password(cfg['ADMIN_PASSWORD']), exp_iso, now_iso)
        )
        admin_id = c.lastrowid
        c.execute('INSERT INTO store_profiles (user_id, name) VALUES (?, ?)', (admin_id, 'Admin Central POS'))

    conn.commit()
    conn.close()


def mp_api_request(method, path, token, payload=None):
    url = f"https://api.mercadopago.com{path}"
    data = json.dumps(payload).encode('utf-8') if payload is not None else None
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'User-Agent': 'ComprobantesPOS-SaaS/2.0'
    }
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.status, json.loads(resp.read().decode('utf-8'))


def activate_user_subscription(conn, user_id, payment_id, amount, raw_data):
    user = conn.execute('SELECT id, subscription_status, subscription_expires_at FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        return False

    # Avoid double-crediting same payment_id
    if payment_id:
        already = conn.execute('SELECT id FROM subscription_payments WHERE mp_payment_id = ?', (str(payment_id),)).fetchone()
        if already:
            return True

    now = utc_now()
    base_date = now
    if user['subscription_status'] == 'active' and user['subscription_expires_at']:
        try:
            current_exp = datetime.fromisoformat(user['subscription_expires_at'])
            if current_exp.tzinfo is None:
                current_exp = current_exp.replace(tzinfo=timezone.utc)
            if current_exp > now:
                base_date = current_exp
        except Exception:
            pass

    new_exp = (base_date + timedelta(days=SUBSCRIPTION_DAYS)).isoformat()

    conn.execute(
        '''UPDATE users
           SET subscription_status = 'active',
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
    return status, days_left, exp_str


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

    def get_base_url(self):
        cfg = load_config()
        if cfg.get('PUBLIC_BASE_URL'):
            return cfg['PUBLIC_BASE_URL'].rstrip('/')
        host = self.headers.get('Host') or f'localhost:{PORT}'
        proto = self.headers.get('X-Forwarded-Proto', 'http')
        return f"{proto}://{host}"

    def get_current_user(self, conn):
        auth = self.headers.get('Authorization', '')
        token = ''
        if auth.startswith('Bearer '):
            token = auth[7:].strip()
        if not token:
            return None
        row = conn.execute(
            '''SELECT u.* FROM sessions s
               JOIN users u ON u.id = s.user_id
               WHERE s.token = ?''',
            (token,)
        ).fetchone()
        return row

    def require_active_user(self, conn):
        user = self.get_current_user(conn)
        if not user:
            self.send_json(401, {'error': 'Sesión expirada o no iniciada.'})
            return None
        status, _, _ = compute_subscription_info(user)
        if status != 'active':
            self.send_json(402, {'error': 'Suscripción inactiva o vencida. Abona $10.000 por 3 meses para activar.'})
            return None
        return user

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == '/api/health':
            cfg = load_config()
            self.send_json(200, {
                'ok': True,
                'mp_platform_configured': bool(cfg.get('PLATFORM_MP_ACCESS_TOKEN')),
                'subscription_price': SUBSCRIPTION_PRICE,
                'subscription_days': SUBSCRIPTION_DAYS
            })
            return

        if path == '/api/auth/me':
            conn = get_db()
            try:
                user = self.get_current_user(conn)
                if not user:
                    self.send_json(401, {'error': 'No autenticado'})
                    return
                status, days_left, exp_str = compute_subscription_info(user)
                self.send_json(200, {
                    'user': {
                        'id': user['id'],
                        'email': user['email'],
                        'role': user['role'],
                        'store_name': user['store_name'],
                        'subscription_status': status,
                        'days_left': days_left,
                        'subscription_expires_at': exp_str
                    }
                })
            finally:
                conn.close()
            return

        if path == '/api/subscription/callback':
            query = parse_qs(parsed.query)
            payment_id = query.get('payment_id', [None])[0] or query.get('collection_id', [None])[0]
            ext_ref = query.get('external_reference', [''])[0]
            cfg = load_config()
            token = cfg.get('PLATFORM_MP_ACCESS_TOKEN', '')
            activated = False

            if payment_id and token and payment_id != 'null':
                try:
                    code, pdata = mp_api_request('GET', f'/v1/payments/{payment_id}', token)
                    if code == 200 and pdata.get('status') == 'approved':
                        ref = pdata.get('external_reference') or ext_ref
                        if ref.startswith('sub_user_') and float(pdata.get('transaction_amount', 0)) >= SUBSCRIPTION_PRICE:
                            uid = int(ref.replace('sub_user_', ''))
                            conn = get_db()
                            try:
                                activated = activate_user_subscription(conn, uid, payment_id, pdata.get('transaction_amount', SUBSCRIPTION_PRICE), pdata)
                            finally:
                                conn.close()
                except Exception as e:
                    print("Callback verification error:", e)

            target = '/?sub=activated' if activated else '/?sub=pending'
            self.send_response(302)
            self.send_header('Location', target)
            self.end_headers()
            return

        if path == '/api/store/bootstrap':
            conn = get_db()
            try:
                user = self.require_active_user(conn)
                if not user:
                    return
                profile = conn.execute('SELECT * FROM store_profiles WHERE user_id = ?', (user['id'],)).fetchone()
                products = conn.execute('SELECT * FROM products WHERE user_id = ? ORDER BY created_at DESC', (user['id'],)).fetchall()
                customers = conn.execute('SELECT * FROM customers WHERE user_id = ? ORDER BY created_at DESC', (user['id'],)).fetchall()
                orders = conn.execute('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 200', (user['id'],)).fetchall()

                self.send_json(200, {
                    'profile': dict(profile) if profile else {},
                    'products': [dict(p) for p in products],
                    'customers': [dict(c) for c in customers],
                    'orders': [dict(o) for o in orders]
                })
            finally:
                conn.close()
            return

        if path.startswith('/api/orders/') and path.endswith('/check-payment'):
            order_id = path.split('/')[3]
            conn = get_db()
            try:
                user = self.require_active_user(conn)
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
                user = self.require_active_user(conn)
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
                    'SELECT name, store_icon, logo_data_url, phone, address, instagram, currency_symbol FROM store_profiles WHERE user_id = ?',
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

        if path == '/api/admin/overview':
            conn = get_db()
            try:
                user = self.get_current_user(conn)
                if not user or user['role'] != 'admin':
                    self.send_json(403, {'error': 'Acceso solo para administrador'})
                    return
                users = conn.execute(
                    'SELECT id, email, role, store_name, subscription_status, subscription_expires_at, mp_last_payment_id, created_at FROM users ORDER BY id DESC'
                ).fetchall()
                payments = conn.execute(
                    '''SELECT sp.*, u.email, u.store_name
                       FROM subscription_payments sp
                       JOIN users u ON u.id = sp.user_id
                       ORDER BY sp.id DESC LIMIT 50'''
                ).fetchall()
                cfg = load_config()
                self.send_json(200, {
                    'users': [dict(u) for u in users],
                    'payments': [dict(p) for p in payments],
                    'config': {
                        'mp_platform_configured': bool(cfg.get('PLATFORM_MP_ACCESS_TOKEN')),
                        'mp_token_masked': (cfg['PLATFORM_MP_ACCESS_TOKEN'][:12] + '...') if cfg.get('PLATFORM_MP_ACCESS_TOKEN') else '',
                        'platform_mp_pay_link': cfg.get('PLATFORM_MP_PAY_LINK', ''),
                        'public_base_url': cfg.get('PUBLIC_BASE_URL', '')
                    }
                })
            finally:
                conn.close()
            return

        # Serve static files cleanly
        if path == '/' or path == '':
            self.path = '/index.html'
        elif path == '/seguimiento':
            self.path = '/seguimiento.html'
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        body = self.read_json_body()

        if path == '/api/auth/register':
            email = (body.get('email') or '').strip().lower()
            password = body.get('password') or ''
            store_name = (body.get('store_name') or '').strip()
            if not email or '@' not in email or len(password) < 4 or not store_name:
                self.send_json(400, {'error': 'Completa un correo válido, nombre de tienda y contraseña (mín. 4 caracteres).'})
                return

            conn = get_db()
            try:
                exists = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
                if exists:
                    self.send_json(409, {'error': 'Ese correo ya está registrado. Inicia sesión.'})
                    return
                now_iso = utc_now().isoformat()
                cur = conn.execute(
                    '''INSERT INTO users (email, password_hash, role, store_name, subscription_status, created_at)
                       VALUES (?, ?, 'merchant', ?, 'pending', ?)''',
                    (email, hash_password(password), store_name, now_iso)
                )
                uid = cur.lastrowid
                conn.execute('INSERT INTO store_profiles (user_id, name) VALUES (?, ?)', (uid, store_name))

                sess_token = secrets.token_urlsafe(32)
                exp_iso = (utc_now() + timedelta(days=30)).isoformat()
                conn.execute(
                    'INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)',
                    (sess_token, uid, now_iso, exp_iso)
                )
                conn.commit()
                self.send_json(201, {
                    'token': sess_token,
                    'user': {
                        'id': uid,
                        'email': email,
                        'role': 'merchant',
                        'store_name': store_name,
                        'subscription_status': 'pending',
                        'days_left': 0
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
                    'INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)',
                    (sess_token, user['id'], now_iso, exp_iso)
                )
                conn.commit()
                status, days_left, exp_str = compute_subscription_info(user)
                self.send_json(200, {
                    'token': sess_token,
                    'user': {
                        'id': user['id'],
                        'email': user['email'],
                        'role': user['role'],
                        'store_name': user['store_name'],
                        'subscription_status': status,
                        'days_left': days_left,
                        'subscription_expires_at': exp_str
                    }
                })
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
                cfg = load_config()
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

                base_url = self.get_base_url()
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
                cfg = load_config()
                if cfg.get('PLATFORM_MP_ACCESS_TOKEN') and user['role'] != 'admin':
                    self.send_json(403, {'error': 'Simulación deshabilitada cuando hay token real configurado.'})
                    return
                pid = f"demo_{secrets.token_hex(5)}"
                activate_user_subscription(conn, user['id'], pid, SUBSCRIPTION_PRICE, {'demo': True})
                updated = conn.execute('SELECT * FROM users WHERE id = ?', (user['id'],)).fetchone()
                status, days_left, exp_str = compute_subscription_info(updated)
                self.send_json(200, {
                    'ok': True,
                    'subscription_status': status,
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
            cfg = load_config()
            mp_token = cfg.get('PLATFORM_MP_ACCESS_TOKEN', '')
            if mp_token and payment_id and topic in ('payment', 'payment.created', 'payment.updated', None):
                try:
                    code, pdata = mp_api_request('GET', f'/v1/payments/{payment_id}', mp_token)
                    if code == 200 and pdata.get('status') == 'approved':
                        ref = pdata.get('external_reference', '')
                        if ref.startswith('sub_user_') and float(pdata.get('transaction_amount', 0)) >= SUBSCRIPTION_PRICE:
                            uid = int(ref.replace('sub_user_', ''))
                            conn = get_db()
                            try:
                                activate_user_subscription(conn, uid, payment_id, pdata.get('transaction_amount', SUBSCRIPTION_PRICE), pdata)
                            finally:
                                conn.close()
                except Exception as e:
                    print("Webhook MP error:", e)
            self.send_json(200, {'received': True})
            return

        if path == '/api/products':
            conn = get_db()
            try:
                user = self.require_active_user(conn)
                if not user:
                    return
                pid = 'prod_' + secrets.token_hex(6)
                now_iso = utc_now().isoformat()
                conn.execute(
                    '''INSERT INTO products (id, user_id, name, price, cost_price, category, stock, min_stock, barcode, sku, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (
                        pid, user['id'],
                        (body.get('name') or '').strip(),
                        float(body.get('price') or 0),
                        float(body.get('cost_price') or 0),
                        (body.get('category') or 'General').strip(),
                        int(body.get('stock') or 0),
                        int(body.get('min_stock') or 3),
                        (body.get('barcode') or '').strip(),
                        (body.get('sku') or body.get('barcode') or '').strip(),
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
                user = self.require_active_user(conn)
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

        if path == '/api/customers':
            conn = get_db()
            try:
                user = self.require_active_user(conn)
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
                user = self.require_active_user(conn)
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
                    qty = int(item.get('quantity') or 1)
                    prod = conn.execute('SELECT id, stock, cost_price FROM products WHERE user_id = ? AND lower(name) = ?', (user['id'], pname.lower())).fetchone()
                    unit_cost = float(item.get('unitCost') if item.get('unitCost') is not None else (prod['cost_price'] if prod else 0))
                    cost_sub = unit_cost * qty
                    total_cost += cost_sub
                    enriched = dict(item)
                    enriched['unitCost'] = unit_cost
                    enriched['costSubtotal'] = cost_sub
                    enriched_items.append(enriched)
                    if prod:
                        new_stock = max(0, int(prod['stock']) - qty)
                        conn.execute('UPDATE products SET stock = ? WHERE id = ?', (new_stock, prod['id']))

                order_total = float(body.get('total') or 0)
                net_profit = order_total - total_cost

                conn.execute(
                    '''INSERT INTO orders (
                           id, user_id, tracking_code, folio_number, customer_name, customer_phone,
                           customer_address, customer_handle, items_json, subtotal, discount_amount,
                           discount_label, total, total_cost, net_profit, payment_status, dispatch_status, notes, created_at
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
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

                # Increment folio
                conn.execute('UPDATE store_profiles SET next_folio_number = ? WHERE user_id = ?', (folio_num + 1, user['id']))

                # Upsert customer in CRM if name/phone provided
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

        if path.startswith('/api/orders/') and path.endswith('/payment-link'):
            order_id = path.split('/')[3]
            conn = get_db()
            try:
                user = self.require_active_user(conn)
                if not user:
                    return
                order = conn.execute('SELECT * FROM orders WHERE id = ? AND user_id = ?', (order_id, user['id'])).fetchone()
                if not order:
                    self.send_json(404, {'error': 'Pedido no encontrado'})
                    return
                profile = conn.execute('SELECT name, mp_access_token FROM store_profiles WHERE user_id = ?', (user['id'],)).fetchone()
                mp_token = profile['mp_access_token'] if profile else ''
                if not mp_token:
                    self.send_json(400, {'error': 'Configura primero tu Access Token de Mercado Pago en la pestaña Comprobante / Mi Tienda.'})
                    return

                base_url = self.get_base_url()
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
                activate_user_subscription(conn, target_id, f"admin_{secrets.token_hex(4)}", SUBSCRIPTION_PRICE, {'manual_admin': True})
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
                save_config(updates)
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
                user = self.require_active_user(conn)
                if not user:
                    return
                fields = [
                    'name', 'store_icon', 'logo_data_url', 'receipt_theme', 'app_palette',
                    'custom_color', 'business_mode', 'phone', 'address',
                    'instagram', 'website', 'currency_symbol', 'next_folio_number',
                    'receipt_footer_message', 'mp_access_token', 'voice_accent', 'voice_template'
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
                user = self.require_active_user(conn)
                if not user:
                    return
                conn.execute(
                    '''UPDATE products
                       SET name = ?, price = ?, cost_price = ?, category = ?, stock = ?, min_stock = ?, barcode = ?, sku = ?
                       WHERE id = ? AND user_id = ?''',
                    (
                        (body.get('name') or '').strip(),
                        float(body.get('price') or 0),
                        float(body.get('cost_price') or 0),
                        (body.get('category') or 'General').strip(),
                        int(body.get('stock') or 0),
                        int(body.get('min_stock') or 3),
                        (body.get('barcode') or '').strip(),
                        (body.get('barcode') or '').strip(),
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
                user = self.require_active_user(conn)
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
                user = self.require_active_user(conn)
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
                user = self.require_active_user(conn)
                if not user:
                    return
                conn.execute('DELETE FROM products WHERE id = ? AND user_id = ?', (pid, user['id']))
                conn.commit()
                self.send_json(200, {'ok': True})
            finally:
                conn.close()
            return
        self.send_json(404, {'error': 'Ruta no encontrada'})


def run():
    init_db()
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.daemon_threads = True
    with socketserver.ThreadingTCPServer(("", PORT), SaaSHandler) as httpd:
        print("=" * 64)
        print(f"[OK] COMPROBANTES POS & DESPACHO SaaS ACTIVO en http://localhost:{PORT}")
        print("Base de datos SQLite lista:", DB_PATH)
        print("=" * 64)
        httpd.serve_forever()


if __name__ == "__main__":
    run()
