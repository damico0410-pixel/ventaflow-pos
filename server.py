import http.server
import socketserver
import os
import sys
import re
import hmac
import math
import json
import time
import base64
import sqlite3
import hashlib
import secrets
import smtplib
import threading
import urllib.request
import urllib.error
from collections import defaultdict, deque
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
MAX_BODY_BYTES = 2_800_000  # Límite estricto anti-saturación de memoria (~2.7 MB)

DATABASE_URL = os.environ.get('DATABASE_URL', '').strip()
IS_POSTGRES = bool(DATABASE_URL)

# Lista blanca estricta de archivos estáticos públicos
PUBLIC_STATIC_FILES = {
    '/index.html': 'text/html; charset=utf-8',
    '/tienda.html': 'text/html; charset=utf-8',
    '/seguimiento.html': 'text/html; charset=utf-8',
    '/manifest.json': 'application/manifest+json; charset=utf-8',
    '/sw.js': 'application/javascript; charset=utf-8',
    '/icon.svg': 'image/svg+xml',
}

MP_SUPPORTED_CURRENCIES = {'ARS', 'BRL', 'CLP', 'COP', 'MXN', 'PEN', 'UYU'}


def utc_now():
    return datetime.now(timezone.utc)


def slugify(text):
    s = (text or '').strip().lower()
    replacements = {'á': 'a', 'é': 'e', 'í': 'i', 'ó': 'o', 'ú': 'u', 'ñ': 'n', 'ü': 'u', 'ç': 'c'}
    for k, v in replacements.items():
        s = s.replace(k, v)
    s = re.sub(r'[^a-z0-9]+', '-', s).strip('-')
    return (s[:48].strip('-')) or ('tienda-' + secrets.token_hex(3))


def append_timeline_event(existing_json, status, title, detail=''):
    try:
        events = json.loads(existing_json or '[]')
        if not isinstance(events, list):
            events = []
    except Exception:
        events = []
    events.append({
        'status': str(status)[:32],
        'title': str(title)[:120],
        'detail': str(detail)[:220],
        'at': utc_now().isoformat()
    })
    return json.dumps(events[-30:], ensure_ascii=False)


# ================= CRIPTOGRAFÍA AUTENTICADA (PBKDF2 + AES-STREAM/HMAC-SHA256) =================

_CACHED_MASTER_KEY = None
_CRYPTO_LOCK = threading.Lock()


def hash_password(password, salt=None):
    if not salt:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac('sha256', str(password).encode('utf-8'), salt.encode('utf-8'), 150000)
    return f"{salt}${dk.hex()}"


def verify_password(password, stored_hash):
    if not stored_hash or '$' not in stored_hash:
        return False
    try:
        salt, _ = stored_hash.split('$', 1)
        cand_150 = hash_password(str(password), salt)
        if secrets.compare_digest(cand_150, stored_hash):
            return True
        dk_120 = hashlib.pbkdf2_hmac('sha256', str(password).encode('utf-8'), salt.encode('utf-8'), 120000)
        return secrets.compare_digest(f"{salt}${dk_120.hex()}", stored_hash)
    except Exception:
        return False


def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(enc_key, nonce + counter.to_bytes(4, 'big'), hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def get_master_key(conn=None) -> bytes:
    global _CACHED_MASTER_KEY
    with _CRYPTO_LOCK:
        if _CACHED_MASTER_KEY is not None:
            return _CACHED_MASTER_KEY
        env_secret = os.environ.get('APP_MASTER_SECRET', '').strip()
        if env_secret:
            _CACHED_MASTER_KEY = hashlib.sha256(env_secret.encode('utf-8')).digest()
            return _CACHED_MASTER_KEY

        own = False
        if conn is None:
            try:
                conn = get_db()
                own = True
            except Exception:
                conn = None
        try:
            if conn is not None:
                row = conn.execute("SELECT value FROM platform_settings WHERE key = 'MASTER_KEY_HEX'").fetchone()
                if row and row['value']:
                    _CACHED_MASTER_KEY = bytes.fromhex(row['value'])
                    return _CACHED_MASTER_KEY
                new_hex = secrets.token_hex(32)
                conn.execute(
                    '''INSERT INTO platform_settings (key, value) VALUES ('MASTER_KEY_HEX', ?)
                       ON CONFLICT(key) DO NOTHING''',
                    (new_hex,)
                )
                conn.commit()
                row2 = conn.execute("SELECT value FROM platform_settings WHERE key = 'MASTER_KEY_HEX'").fetchone()
                _CACHED_MASTER_KEY = bytes.fromhex(row2['value'])
                return _CACHED_MASTER_KEY
        except Exception:
            if IS_POSTGRES and conn is not None:
                try:
                    conn.rollback()
                except Exception:
                    pass
        finally:
            if own and conn is not None:
                conn.close()
        return hashlib.sha256(b'ventaflow-fallback-local-key').digest()


def encrypt_secret(plaintext: str, conn=None) -> str:
    if not plaintext:
        return ''
    if str(plaintext).startswith('enc:v1:'):
        return str(plaintext)
    master = get_master_key(conn)
    enc_key = hmac.new(master, b'vf-enc-v1', hashlib.sha256).digest()
    mac_key = hmac.new(master, b'vf-mac-v1', hashlib.sha256).digest()
    nonce = secrets.token_bytes(16)
    raw = str(plaintext).encode('utf-8')
    stream = _keystream(enc_key, nonce, len(raw))
    cipher = bytes(a ^ b for a, b in zip(raw, stream))
    ct_b64 = base64.urlsafe_b64encode(cipher).decode('ascii')
    nonce_hex = nonce.hex()
    tag = hmac.new(mac_key, f"enc:v1:{nonce_hex}:{ct_b64}".encode('ascii'), hashlib.sha256).hexdigest()
    return f"enc:v1:{nonce_hex}:{ct_b64}:{tag}"


def decrypt_secret(stored: str, conn=None) -> str:
    if not stored:
        return ''
    s = str(stored)
    if not s.startswith('enc:v1:'):
        return s
    try:
        parts = s.split(':')
        if len(parts) != 5:
            return ''
        _, _, nonce_hex, ct_b64, tag = parts
        master = get_master_key(conn)
        enc_key = hmac.new(master, b'vf-enc-v1', hashlib.sha256).digest()
        mac_key = hmac.new(master, b'vf-mac-v1', hashlib.sha256).digest()
        expected_tag = hmac.new(mac_key, f"enc:v1:{nonce_hex}:{ct_b64}".encode('ascii'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_tag, tag):
            return ''
        nonce = bytes.fromhex(nonce_hex)
        cipher = base64.urlsafe_b64decode(ct_b64.encode('ascii'))
        stream = _keystream(enc_key, nonce, len(cipher))
        plain = bytes(a ^ b for a, b in zip(cipher, stream))
        return plain.decode('utf-8')
    except Exception:
        return ''


def mask_secret(secret_str: str) -> str:
    if not secret_str:
        return ''
    s = str(secret_str)
    if len(s) <= 8:
        return '••••••••'
    return f"{s[:8]}••••{s[-4:]}"


# ================= ESCUDO ANTI-FUERZA BRUTA & RATE LIMITER EN MEMORIA =================

class SecurityShield:
    def __init__(self):
        self._lock = threading.Lock()
        self._ip_hits = defaultdict(deque)
        self._failed_auth = defaultdict(deque)
        self._lockouts = {}

    def check_rate(self, bucket: str, ip: str, limit: int, window_sec: int = 60) -> bool:
        now = time.monotonic()
        key = f"{bucket}:{ip}"
        with self._lock:
            dq = self._ip_hits[key]
            cutoff = now - window_sec
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= limit:
                return False
            dq.append(now)
            if len(self._ip_hits) > 4000:
                stale_keys = [k for k, v in self._ip_hits.items() if not v or v[-1] < cutoff]
                for sk in stale_keys:
                    del self._ip_hits[sk]
            return True

    def is_locked_out(self, ip: str, identifier: str = '') -> int:
        now = time.monotonic()
        keys = [f"ip:{ip}"]
        if identifier:
            keys.append(f"id:{identifier.lower()[:80]}")
        with self._lock:
            rem = 0
            for k in keys:
                until = self._lockouts.get(k, 0)
                if until > now:
                    rem = max(rem, int(until - now) + 1)
                elif k in self._lockouts:
                    del self._lockouts[k]
            return rem

    def record_auth_failure(self, ip: str, identifier: str = ''):
        now = time.monotonic()
        keys = [f"ip:{ip}"]
        if identifier:
            keys.append(f"id:{identifier.lower()[:80]}")
        with self._lock:
            for k in keys:
                dq = self._failed_auth[k]
                cutoff = now - 300
                while dq and dq[0] < cutoff:
                    dq.popleft()
                dq.append(now)
                if len(dq) >= 6:
                    self._lockouts[k] = now + 300

    def clear_auth_failures(self, ip: str, identifier: str = ''):
        with self._lock:
            for k in (f"ip:{ip}", f"id:{identifier.lower()[:80]}"):
                self._failed_auth.pop(k, None)
                self._lockouts.pop(k, None)


SHIELD = SecurityShield()


# ================= POOL DE CONEXIONES POSTGRESQL + SQLITE WRAPPER =================

_PG_POOL = None
_PG_POOL_LOCK = threading.Lock()


def _get_pg_pool():
    global _PG_POOL
    if _PG_POOL is not None:
        return _PG_POOL
    with _PG_POOL_LOCK:
        if _PG_POOL is None:
            import psycopg2
            import psycopg2.pool
            import psycopg2.extras
            _PG_POOL = psycopg2.pool.ThreadedConnectionPool(
                minconn=1,
                maxconn=12,
                dsn=DATABASE_URL,
                cursor_factory=psycopg2.extras.RealDictCursor
            )
        return _PG_POOL


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
    def __init__(self):
        import psycopg2
        import psycopg2.extras
        self._pool = _get_pg_pool()
        self._from_pool = True
        conn = self._pool.getconn()
        try:
            if conn.closed:
                self._pool.putconn(conn, close=True)
                conn = self._pool.getconn()
            else:
                with conn.cursor() as chk:
                    chk.execute('SELECT 1')
                conn.rollback()
        except Exception:
            try:
                self._pool.putconn(conn, close=True)
            except Exception:
                pass
            conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
            self._from_pool = False
        self._conn = conn

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
        if self._conn is None:
            return
        try:
            if not self._conn.closed:
                self._conn.rollback()
        except Exception:
            pass
        if self._from_pool and self._pool is not None:
            try:
                self._pool.putconn(self._conn, close=bool(self._conn.closed))
            except Exception:
                try:
                    self._conn.close()
                except Exception:
                    pass
        else:
            try:
                self._conn.close()
            except Exception:
                pass
        self._conn = None


def get_db():
    if IS_POSTGRES:
        return PgConnWrapper()
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
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
                for k, v in saved.items():
                    if v is not None and v != "" and k != 'MASTER_KEY_HEX':
                        cfg[k] = v
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
                k, val = r['key'], r['value']
                if k == 'MASTER_KEY_HEX' or val is None or val == '':
                    continue
                if k in ('PLATFORM_MP_ACCESS_TOKEN', 'SMTP_PASS'):
                    cfg[k] = decrypt_secret(val, conn)
                else:
                    cfg[k] = val
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
            val_str = str(v)
            if k in ('PLATFORM_MP_ACCESS_TOKEN', 'SMTP_PASS') and val_str:
                val_str = encrypt_secret(val_str, conn)
            conn.execute(
                '''INSERT INTO platform_settings (key, value) VALUES (?, ?)
                   ON CONFLICT(key) DO UPDATE SET value = excluded.value''',
                (str(k), val_str)
            )
        conn.commit()
    finally:
        if own_conn:
            conn.close()


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


def restock_order_items(conn, user_id, items_json_str):
    try:
        items = json.loads(items_json_str or '[]')
    except Exception:
        items = []
    for item in items:
        pname = (item.get('productName') or '').strip()
        base_name = pname.split(' (')[0].strip()
        variant_sel = (item.get('variantName') or '').strip()
        qty = max(1, int(item.get('quantity') or 1))
        prod = conn.execute(
            'SELECT id, stock, variants_json FROM products WHERE user_id = ? AND (lower(name) = ? OR lower(name) = ?)',
            (user_id, pname.lower(), base_name.lower())
        ).fetchone()
        if prod:
            try:
                vlist = json.loads(prod['variants_json'] or '[]')
            except Exception:
                vlist = []
            if vlist and variant_sel:
                matched = False
                for v in vlist:
                    if str(v.get('name', '')).lower() == variant_sel.lower():
                        v['stock'] = int(v.get('stock') or 0) + qty
                        matched = True
                if matched:
                    new_stock = sum(max(0, int(v.get('stock') or 0)) for v in vlist)
                    conn.execute('UPDATE products SET stock = ?, variants_json = ? WHERE id = ?', (new_stock, json.dumps(vlist, ensure_ascii=False), prod['id']))
                    continue
            conn.execute('UPDATE products SET stock = ? WHERE id = ?', (int(prod['stock'] or 0) + qty, prod['id']))


def upsert_customer_record(conn, user_id, cname, cphone, caddr, chandle='', ccp='', ccity='', cprov='', inc_order=True):
    if not cname or cname.strip().lower() == 'cliente':
        return
    cname_clean = cname.strip()[:100]
    existing = conn.execute(
        'SELECT * FROM customers WHERE user_id = ? AND lower(name) = ?',
        (user_id, cname_clean.lower())
    ).fetchone()
    now_iso = utc_now().isoformat()
    if existing:
        new_count = int(existing['orders_count'] if 'orders_count' in existing.keys() and existing['orders_count'] else 1) + (1 if inc_order else 0)
        conn.execute(
            '''UPDATE customers
               SET phone = COALESCE(NULLIF(?, ''), phone),
                   address = COALESCE(NULLIF(?, ''), address),
                   handle = COALESCE(NULLIF(?, ''), handle),
                   postal_code = COALESCE(NULLIF(?, ''), postal_code),
                   city = COALESCE(NULLIF(?, ''), city),
                   province = COALESCE(NULLIF(?, ''), province),
                   orders_count = ?
               WHERE id = ?''',
            (cphone, caddr, chandle, ccp, ccity, cprov, new_count, existing['id'])
        )
    else:
        conn.execute(
            '''INSERT INTO customers (id, user_id, name, phone, address, handle, postal_code, city, province, orders_count, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)''',
            ('cust_' + secrets.token_hex(6), user_id, cname_clean, cphone, caddr, chandle, ccp, ccity, cprov, now_iso)
        )


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
            origin_postal_code TEXT DEFAULT '',
            origin_province TEXT DEFAULT '',
            instagram TEXT DEFAULT '',
            website TEXT DEFAULT '',
            country_code TEXT DEFAULT 'AR',
            currency_code TEXT DEFAULT 'ARS',
            currency_symbol TEXT DEFAULT '$',
            tax_label TEXT DEFAULT '',
            tax_rate REAL DEFAULT 0,
            bank_alias TEXT DEFAULT '',
            bank_holder TEXT DEFAULT '',
            external_pay_link TEXT DEFAULT '',
            cash_on_delivery INTEGER DEFAULT 1,
            shipping_flat_rate REAL DEFAULT 0,
            shipping_branch_rate REAL DEFAULT 0,
            free_shipping_min REAL DEFAULT 0,
            allow_pickup INTEGER DEFAULT 1,
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
            postal_code TEXT DEFAULT '',
            city TEXT DEFAULT '',
            province TEXT DEFAULT '',
            handle TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            orders_count INTEGER DEFAULT 1,
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
            customer_postal_code TEXT DEFAULT '',
            customer_city TEXT DEFAULT '',
            customer_province TEXT DEFAULT '',
            branch_name TEXT DEFAULT '',
            customer_handle TEXT DEFAULT '',
            items_json TEXT NOT NULL,
            subtotal REAL NOT NULL,
            discount_amount REAL DEFAULT 0,
            discount_label TEXT DEFAULT '',
            shipping_cost REAL DEFAULT 0,
            tax_amount REAL DEFAULT 0,
            total REAL NOT NULL,
            total_cost REAL DEFAULT 0,
            net_profit REAL DEFAULT 0,
            payment_status TEXT DEFAULT 'pending',
            payment_method TEXT DEFAULT 'mercadopago',
            mp_payment_id TEXT DEFAULT '',
            mp_payment_link TEXT DEFAULT '',
            transfer_proof_url TEXT DEFAULT '',
            transfer_reference TEXT DEFAULT '',
            delivery_method TEXT DEFAULT 'delivery',
            dispatch_status TEXT DEFAULT 'to_prepare',
            shipping_carrier TEXT DEFAULT '',
            shipping_tracking TEXT DEFAULT '',
            timeline_json TEXT DEFAULT '[]',
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

    migrations = [
        "ALTER TABLE users ADD COLUMN recovery_pin_hash TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN is_trial INTEGER DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN scope TEXT DEFAULT 'owner'",
        "ALTER TABLE products ADD COLUMN cost_price REAL DEFAULT 0",
        "ALTER TABLE products ADD COLUMN image_url TEXT DEFAULT ''",
        "ALTER TABLE products ADD COLUMN variants_json TEXT DEFAULT '[]'",
        "ALTER TABLE customers ADD COLUMN postal_code TEXT DEFAULT ''",
        "ALTER TABLE customers ADD COLUMN city TEXT DEFAULT ''",
        "ALTER TABLE customers ADD COLUMN province TEXT DEFAULT ''",
        "ALTER TABLE customers ADD COLUMN orders_count INTEGER DEFAULT 1",
        "ALTER TABLE orders ADD COLUMN total_cost REAL DEFAULT 0",
        "ALTER TABLE orders ADD COLUMN net_profit REAL DEFAULT 0",
        "ALTER TABLE orders ADD COLUMN source TEXT DEFAULT 'pos'",
        "ALTER TABLE orders ADD COLUMN shipping_cost REAL DEFAULT 0",
        "ALTER TABLE orders ADD COLUMN tax_amount REAL DEFAULT 0",
        "ALTER TABLE orders ADD COLUMN payment_method TEXT DEFAULT 'mercadopago'",
        "ALTER TABLE orders ADD COLUMN delivery_method TEXT DEFAULT 'delivery'",
        "ALTER TABLE orders ADD COLUMN customer_postal_code TEXT DEFAULT ''",
        "ALTER TABLE orders ADD COLUMN customer_city TEXT DEFAULT ''",
        "ALTER TABLE orders ADD COLUMN customer_province TEXT DEFAULT ''",
        "ALTER TABLE orders ADD COLUMN branch_name TEXT DEFAULT ''",
        "ALTER TABLE orders ADD COLUMN transfer_proof_url TEXT DEFAULT ''",
        "ALTER TABLE orders ADD COLUMN transfer_reference TEXT DEFAULT ''",
        "ALTER TABLE orders ADD COLUMN timeline_json TEXT DEFAULT '[]'",
        "ALTER TABLE store_profiles ADD COLUMN app_palette TEXT DEFAULT 'violet'",
        "ALTER TABLE store_profiles ADD COLUMN custom_color TEXT DEFAULT '#7C3AED'",
        "ALTER TABLE store_profiles ADD COLUMN business_mode TEXT DEFAULT 'NUEVO PEDIDO PARA DESPACHO'",
        "ALTER TABLE store_profiles ADD COLUMN slug TEXT DEFAULT ''",
        "ALTER TABLE store_profiles ADD COLUMN staff_pin TEXT DEFAULT ''",
        "ALTER TABLE store_profiles ADD COLUMN country_code TEXT DEFAULT 'AR'",
        "ALTER TABLE store_profiles ADD COLUMN currency_code TEXT DEFAULT 'ARS'",
        "ALTER TABLE store_profiles ADD COLUMN tax_label TEXT DEFAULT ''",
        "ALTER TABLE store_profiles ADD COLUMN tax_rate REAL DEFAULT 0",
        "ALTER TABLE store_profiles ADD COLUMN bank_alias TEXT DEFAULT ''",
        "ALTER TABLE store_profiles ADD COLUMN bank_holder TEXT DEFAULT ''",
        "ALTER TABLE store_profiles ADD COLUMN external_pay_link TEXT DEFAULT ''",
        "ALTER TABLE store_profiles ADD COLUMN cash_on_delivery INTEGER DEFAULT 1",
        "ALTER TABLE store_profiles ADD COLUMN shipping_flat_rate REAL DEFAULT 0",
        "ALTER TABLE store_profiles ADD COLUMN shipping_branch_rate REAL DEFAULT 0",
        "ALTER TABLE store_profiles ADD COLUMN free_shipping_min REAL DEFAULT 0",
        "ALTER TABLE store_profiles ADD COLUMN allow_pickup INTEGER DEFAULT 1",
        "ALTER TABLE store_profiles ADD COLUMN origin_postal_code TEXT DEFAULT ''",
        "ALTER TABLE store_profiles ADD COLUMN origin_province TEXT DEFAULT ''",
    ]
    for alter_sql in migrations:
        try:
            c.execute(alter_sql)
            conn.commit()
        except Exception:
            if IS_POSTGRES:
                conn.rollback()

    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_products_user ON products(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_orders_user_created ON orders(user_id, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_orders_tracking ON orders(tracking_code)",
        "CREATE INDEX IF NOT EXISTS idx_customers_user ON customers(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_expenses_user ON expenses(user_id, expense_date)",
        "CREATE INDEX IF NOT EXISTS idx_store_slug ON store_profiles(slug)",
        "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)",
    ]
    for idx_sql in indexes:
        try:
            c.execute(idx_sql)
            conn.commit()
        except Exception:
            if IS_POSTGRES:
                conn.rollback()

    get_master_key(conn)
    plain_tokens = conn.execute(
        "SELECT user_id, mp_access_token FROM store_profiles WHERE mp_access_token IS NOT NULL AND mp_access_token != ''"
    ).fetchall()
    for pt in plain_tokens:
        raw_tok = pt['mp_access_token']
        if raw_tok and not str(raw_tok).startswith('enc:v1:'):
            conn.execute(
                'UPDATE store_profiles SET mp_access_token = ? WHERE user_id = ?',
                (encrypt_secret(raw_tok, conn), pt['user_id'])
            )
    conn.commit()

    missing_slugs = conn.execute("SELECT user_id, name FROM store_profiles WHERE slug IS NULL OR slug = ''").fetchall()
    for row in missing_slugs:
        new_slug = ensure_unique_slug(conn, row['name'], row['user_id'])
        conn.execute('UPDATE store_profiles SET slug = ? WHERE user_id = ?', (new_slug, row['user_id']))
    conn.commit()

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

    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                legacy = json.load(f)
            save_config(legacy, conn)
            os.remove(CONFIG_PATH)
        except Exception:
            pass

    conn.close()


def sanitize_profile_for_client(profile_row, conn=None, is_staff=False):
    if not profile_row:
        return {}
    d = dict(profile_row)
    raw_mp = decrypt_secret(d.get('mp_access_token') or '', conn)
    d['mp_connected'] = bool(raw_mp)
    d['mp_token_masked'] = mask_secret(raw_mp) if not is_staff else ''
    d['mp_access_token'] = ''
    if is_staff:
        d['staff_pin'] = ''
    return d


def resolve_mp_currency(profile_row):
    code = ((profile_row['currency_code'] if profile_row and 'currency_code' in profile_row.keys() else '') or 'ARS').upper().strip()
    return code if code in MP_SUPPORTED_CURRENCIES else 'ARS'


def mp_api_request(method, path, token, payload=None):
    url = f"https://api.mercadopago.com{path}"
    data = json.dumps(payload).encode('utf-8') if payload is not None else None
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'User-Agent': 'VentaFlowPOS-SaaS/5.0'
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
            time.sleep(540)
            try:
                cfg = load_config()
                base = (cfg.get('PUBLIC_BASE_URL') or os.environ.get('RENDER_EXTERNAL_URL') or '').rstrip('/')
                if base.startswith('https://'):
                    req = urllib.request.Request(f"{base}/api/health", headers={'User-Agent': 'VentaFlow-KeepAlive/5.0'})
                    with urllib.request.urlopen(req, timeout=10) as _:
                        pass
            except Exception:
                pass

    t = threading.Thread(target=_loop, daemon=True)
    t.start()


class PayloadTooLargeError(Exception):
    pass


class SaaSHandler(http.server.BaseHTTPRequestHandler):
    server_version = "VentaFlowSecure/5.0"
    sys_version = ""

    def setup(self):
        super().setup()
        try:
            self.request.settimeout(15.0)
        except Exception:
            pass

    def log_message(self, fmt, *args):
        sys.stdout.write("%s - [%s] %s\n" % (self.get_client_ip(), self.log_date_time_string(), fmt % args))

    def get_client_ip(self) -> str:
        xff = self.headers.get('X-Forwarded-For', '')
        if xff:
            return xff.split(',')[0].strip()[:64]
        return (self.client_address[0] if self.client_address else '0.0.0.0')[:64]

    def send_security_headers(self):
        origin = self.headers.get('Origin', '')
        host = self.headers.get('Host', '')
        if origin and (host and (origin == f"https://{host}" or origin == f"http://{host}") or origin.startswith('http://localhost') or origin.startswith('http://127.0.0.1')):
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Vary', 'Origin')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
        self.send_header('Permissions-Policy', 'camera=(self), microphone=(), geolocation=(), payment=()')
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin-allow-popups')
        if self.headers.get('X-Forwarded-Proto') == 'https':
            self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        self.send_header(
            'Content-Security-Policy',
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data: blob: https:; "
            "connect-src 'self' https://api.mercadopago.com; "
            "frame-ancestors 'none'; object-src 'none'; base-uri 'self';"
        )

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_security_headers()
        self.end_headers()

    def send_json(self, code, payload, extra_headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_security_headers()
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        if extra_headers:
            for hk, hv in extra_headers.items():
                self.send_header(hk, hv)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def serve_static_allowlisted(self, route_path: str, head_only: bool = False):
        content_type = PUBLIC_STATIC_FILES.get(route_path)
        if not content_type:
            self.send_json(403, {'error': 'Acceso denegado por política de seguridad.'})
            return
        rel = route_path.lstrip('/')
        full_path = os.path.abspath(os.path.join(BASE_DIR, rel))
        if not full_path.startswith(os.path.abspath(BASE_DIR) + os.sep) or not os.path.isfile(full_path):
            self.send_json(404, {'error': 'Recurso no encontrado.'})
            return
        with open(full_path, 'rb') as f:
            content = f.read()
        self.send_response(200)
        self.send_security_headers()
        self.send_header('Content-Type', content_type)
        if route_path.endswith('.html') or route_path == '/sw.js':
            self.send_header('Cache-Control', 'no-cache')
        else:
            self.send_header('Cache-Control', 'public, max-age=3600')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        if not head_only:
            self.wfile.write(content)

    def read_json_body(self):
        length = int(self.headers.get('Content-Length', 0) or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY_BYTES:
            raise PayloadTooLargeError()
        raw = self.rfile.read(length).decode('utf-8', errors='replace')
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
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
        if not token or len(token) > 128:
            return None, None
        row = conn.execute(
            '''SELECT u.*, s.scope AS session_scope, s.expires_at AS session_expires_at
               FROM sessions s
               JOIN users u ON u.id = s.user_id
               WHERE s.token = ?''',
            (token,)
        ).fetchone()
        if not row:
            return None, None
        try:
            exp_dt = datetime.fromisoformat(row['session_expires_at'])
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if exp_dt <= utc_now():
                conn.execute('DELETE FROM sessions WHERE token = ?', (token,))
                conn.commit()
                return None, None
        except Exception:
            pass
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

    def check_global_shield(self, path: str) -> bool:
        ip = self.get_client_ip()
        if path.startswith('/api/'):
            if not SHIELD.check_rate('api_global', ip, limit=180, window_sec=60):
                self.send_json(429, {'error': 'Demasiadas solicitudes simultáneas desde tu red. Aguarda unos segundos.'})
                return False
        return True

    def do_HEAD(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == '/api/health':
            self.send_response(200)
            self.send_security_headers()
            self.end_headers()
            return
        if path in ('/', ''):
            path = '/index.html'
        elif path == '/seguimiento':
            path = '/seguimiento.html'
        elif path == '/tienda' or path.startswith('/tienda/'):
            path = '/tienda.html'
        self.serve_static_allowlisted(path, head_only=True)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if not self.check_global_shield(path):
            return

        if path == '/api/health':
            conn = get_db()
            try:
                cfg = load_config(conn)
                trial_days = int(cfg.get('TRIAL_DAYS') or DEFAULT_TRIAL_DAYS)
                self.send_json(200, {
                    'ok': True,
                    'version': '5.0-autopilot',
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
            self.send_security_headers()
            self.send_header('Location', target)
            self.end_headers()
            return

        if path == '/api/store/bootstrap':
            conn = get_db()
            try:
                user, scope = self.require_active_user(conn)
                if not user:
                    return
                is_staff = (scope == 'staff' and user['role'] != 'admin')
                profile = conn.execute('SELECT * FROM store_profiles WHERE user_id = ?', (user['id'],)).fetchone()
                products = conn.execute('SELECT * FROM products WHERE user_id = ? ORDER BY created_at DESC', (user['id'],)).fetchall()
                customers = conn.execute('SELECT * FROM customers WHERE user_id = ? ORDER BY orders_count DESC, created_at DESC', (user['id'],)).fetchall()
                orders = conn.execute('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 300', (user['id'],)).fetchall()
                expenses = conn.execute('SELECT * FROM expenses WHERE user_id = ? ORDER BY expense_date DESC, created_at DESC LIMIT 300', (user['id'],)).fetchall()

                prof_dict = sanitize_profile_for_client(profile, conn, is_staff=is_staff)
                prods_list = [dict(p) for p in products]
                orders_list = [dict(o) for o in orders]
                expenses_list = [dict(e) for e in expenses]

                if is_staff:
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

        if path == '/api/orders/poll-payments':
            conn = get_db()
            try:
                user, scope = self.require_active_user(conn)
                if not user:
                    return
                is_staff = (scope == 'staff' and user['role'] != 'admin')
                profile = conn.execute('SELECT mp_access_token FROM store_profiles WHERE user_id = ?', (user['id'],)).fetchone()
                mp_token = decrypt_secret(profile['mp_access_token'], conn) if profile else ''
                newly_paid_ids = []

                # Si tiene MP conectado, consulta pagos recientes aprobados en MP para pedidos pendientes con link
                if mp_token:
                    pendings = conn.execute(
                        "SELECT id, timeline_json FROM orders WHERE user_id = ? AND payment_status = 'pending' AND mp_payment_link != '' ORDER BY created_at DESC LIMIT 6",
                        (user['id'],)
                    ).fetchall()
                    if pendings:
                        try:
                            _, res = mp_api_request('GET', '/v1/payments/search?sort=date_created&criteria=desc&limit=15&status=approved', mp_token)
                            approved_by_ref = {}
                            for p in (res.get('results') or []):
                                ref = str(p.get('external_reference') or '')
                                if ref.startswith('order_'):
                                    approved_by_ref[ref[6:]] = p
                            for po in pendings:
                                if po['id'] in approved_by_ref:
                                    pay_obj = approved_by_ref[po['id']]
                                    new_tl = append_timeline_event(po['timeline_json'], 'paid', 'Pago acreditado automáticamente por Mercado Pago', f"Operación #{pay_obj.get('id', '')}")
                                    conn.execute(
                                        "UPDATE orders SET payment_status = 'paid', mp_payment_id = ?, timeline_json = ? WHERE id = ?",
                                        (str(pay_obj.get('id', '')), new_tl, po['id'])
                                    )
                                    newly_paid_ids.append(po['id'])
                            if newly_paid_ids:
                                conn.commit()
                        except Exception:
                            pass

                recent_orders = conn.execute(
                    'SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 60',
                    (user['id'],)
                ).fetchall()
                out_orders = [dict(o) for o in recent_orders]
                if is_staff:
                    for o in out_orders:
                        o['total_cost'] = 0
                        o['net_profit'] = 0
                self.send_json(200, {'orders': out_orders, 'newly_paid_ids': newly_paid_ids})
            finally:
                conn.close()
            return

        if path == '/api/store/backup':
            conn = get_db()
            try:
                user, _ = self.require_active_user(conn, owner_only=True)
                if not user:
                    return
                profile = conn.execute('SELECT * FROM store_profiles WHERE user_id = ?', (user['id'],)).fetchone()
                products = conn.execute('SELECT * FROM products WHERE user_id = ? ORDER BY created_at DESC', (user['id'],)).fetchall()
                customers = conn.execute('SELECT * FROM customers WHERE user_id = ? ORDER BY created_at DESC', (user['id'],)).fetchall()
                orders = conn.execute('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC', (user['id'],)).fetchall()
                expenses = conn.execute('SELECT * FROM expenses WHERE user_id = ? ORDER BY expense_date DESC', (user['id'],)).fetchall()
                self.send_json(200, {
                    'backup_version': '5.0',
                    'exported_at': utc_now().isoformat(),
                    'store': sanitize_profile_for_client(profile, conn, is_staff=True),
                    'products': [dict(p) for p in products],
                    'customers': [dict(c) for c in customers],
                    'orders': [dict(o) for o in orders],
                    'expenses': [dict(e) for e in expenses]
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
                mp_token = decrypt_secret(profile['mp_access_token'], conn) if profile else ''
                if not mp_token:
                    self.send_json(400, {'error': 'Configura tu Access Token de Mercado Pago en Cobros MP.'})
                    return

                try:
                    _, res = mp_api_request('GET', f'/v1/payments/search?external_reference=order_{order_id}&status=approved', mp_token)
                    results = res.get('results', [])
                    if results:
                        p = results[0]
                        new_tl = append_timeline_event(order['timeline_json'], 'paid', 'Pago verificado en Mercado Pago', f"Operación #{p.get('id', '')}")
                        conn.execute(
                            "UPDATE orders SET payment_status = 'paid', mp_payment_id = ?, timeline_json = ? WHERE id = ?",
                            (str(p.get('id', '')), new_tl, order_id)
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
                token = decrypt_secret(profile['mp_access_token'], conn) if profile else ''
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
            tracking_code = re.sub(r'[^A-Z0-9\-]', '', path.split('/')[-1].strip().upper())[:24]
            query = parse_qs(parsed.query)
            ret_payment_id = (query.get('payment_id', [None])[0] or query.get('collection_id', [None])[0] or '').strip()
            conn = get_db()
            try:
                order = conn.execute('SELECT * FROM orders WHERE tracking_code = ?', (tracking_code,)).fetchone()
                if not order:
                    self.send_json(404, {'error': 'Pedido no encontrado'})
                    return
                profile_full = conn.execute('SELECT * FROM store_profiles WHERE user_id = ?', (order['user_id'],)).fetchone()

                # Verificación automática instantánea al volver el cliente desde Mercado Pago
                if ret_payment_id and ret_payment_id != 'null' and order['payment_status'] != 'paid' and profile_full:
                    mp_tok = decrypt_secret(profile_full['mp_access_token'], conn)
                    if mp_tok:
                        try:
                            c_mp, pdata = mp_api_request('GET', f'/v1/payments/{ret_payment_id}', mp_tok)
                            if c_mp == 200 and pdata.get('status') == 'approved' and pdata.get('external_reference') == f"order_{order['id']}":
                                new_tl = append_timeline_event(order['timeline_json'], 'paid', 'Pago confirmado automáticamente por Mercado Pago', f"Operación #{ret_payment_id}")
                                conn.execute(
                                    "UPDATE orders SET payment_status = 'paid', mp_payment_id = ?, timeline_json = ? WHERE id = ?",
                                    (str(ret_payment_id), new_tl, order['id'])
                                )
                                conn.commit()
                                order = conn.execute('SELECT * FROM orders WHERE id = ?', (order['id'],)).fetchone()
                        except Exception:
                            pass

                profile = conn.execute(
                    '''SELECT name, slug, store_icon, logo_data_url, phone, address, instagram,
                              currency_symbol, currency_code, bank_alias, bank_holder, external_pay_link,
                              tax_label, shipping_flat_rate, shipping_branch_rate, free_shipping_min, allow_pickup
                       FROM store_profiles WHERE user_id = ?''',
                    (order['user_id'],)
                ).fetchone()
                try:
                    tl = json.loads(order['timeline_json'] or '[]')
                except Exception:
                    tl = []
                if not tl:
                    tl = [{'status': 'created', 'title': 'Pedido registrado', 'detail': f"Folio {order['folio_number']}", 'at': order['created_at']}]

                self.send_json(200, {
                    'order': {
                        'tracking_code': order['tracking_code'],
                        'folio_number': order['folio_number'],
                        'customer_name': order['customer_name'],
                        'customer_address': order['customer_address'],
                        'customer_postal_code': order['customer_postal_code'] or '',
                        'customer_city': order['customer_city'] or '',
                        'customer_province': order['customer_province'] or '',
                        'branch_name': order['branch_name'] or '',
                        'items': json.loads(order['items_json']),
                        'subtotal': order['subtotal'],
                        'discount_amount': order['discount_amount'],
                        'discount_label': order['discount_label'],
                        'shipping_cost': order['shipping_cost'] or 0,
                        'tax_amount': order['tax_amount'] or 0,
                        'total': order['total'],
                        'payment_status': order['payment_status'],
                        'payment_method': order['payment_method'] or 'mercadopago',
                        'mp_payment_link': order['mp_payment_link'],
                        'has_transfer_proof': bool(order['transfer_proof_url']),
                        'transfer_reference': order['transfer_reference'] or '',
                        'delivery_method': order['delivery_method'] or 'delivery',
                        'dispatch_status': order['dispatch_status'],
                        'shipping_carrier': order['shipping_carrier'],
                        'shipping_tracking': order['shipping_tracking'],
                        'timeline': tl,
                        'notes': order['notes'],
                        'created_at': order['created_at']
                    },
                    'store': dict(profile) if profile else {}
                })
            finally:
                conn.close()
            return

        if path.startswith('/api/public/store/'):
            slug = re.sub(r'[^a-z0-9\-]', '', path.split('/')[4].strip().lower())[:64]
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

                mp_tok = decrypt_secret(profile['mp_access_token'], conn)
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
                        'country_code': profile['country_code'] or 'AR',
                        'currency_code': profile['currency_code'] or 'ARS',
                        'currency_symbol': profile['currency_symbol'] or '$',
                        'tax_label': profile['tax_label'] or '',
                        'tax_rate': float(profile['tax_rate'] or 0),
                        'bank_alias': profile['bank_alias'] or '',
                        'bank_holder': profile['bank_holder'] or '',
                        'external_pay_link': profile['external_pay_link'] or '',
                        'cash_on_delivery': bool(profile['cash_on_delivery']),
                        'shipping_flat_rate': float(profile['shipping_flat_rate'] or 0),
                        'shipping_branch_rate': float(profile['shipping_branch_rate'] or 0),
                        'free_shipping_min': float(profile['free_shipping_min'] or 0),
                        'allow_pickup': bool(profile['allow_pickup']),
                        'mp_enabled': bool(mp_tok)
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
                    st, dleft, _, is_tr = compute_subscription_info(u)
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
                        'mp_token_masked': mask_secret(cfg.get('PLATFORM_MP_ACCESS_TOKEN', '')),
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

        if path.startswith('/api/'):
            self.send_json(404, {'error': 'Ruta API no encontrada'})
            return

        if path in ('/', ''):
            route = '/index.html'
        elif path == '/seguimiento':
            route = '/seguimiento.html'
        elif path == '/tienda' or path.startswith('/tienda/'):
            route = '/tienda.html'
        else:
            route = path
        self.serve_static_allowlisted(route)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        ip = self.get_client_ip()

        if not self.check_global_shield(path):
            return

        try:
            body = self.read_json_body()
        except PayloadTooLargeError:
            self.send_json(413, {'error': 'El tamaño de la solicitud supera el límite de seguridad permitido.'})
            return

        if path == '/api/auth/register':
            if not SHIELD.check_rate('auth_reg', ip, limit=8, window_sec=60):
                self.send_json(429, {'error': 'Demasiados registros seguidos. Espera un minuto.'})
                return
            email = (body.get('email') or '').strip().lower()[:120]
            password = str(body.get('password') or '')
            store_name = (body.get('store_name') or '').strip()[:80]
            recovery_pin = str(body.get('recovery_pin') or '').strip()[:32]

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
            email = (body.get('email') or '').strip().lower()[:120]
            password = str(body.get('password') or '')
            wait_s = SHIELD.is_locked_out(ip, email)
            if wait_s > 0:
                self.send_json(429, {'error': f'Por seguridad anti-fuerza bruta, aguarda {wait_s}s antes de volver a intentar.'})
                return
            conn = get_db()
            try:
                user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
                if not user or not verify_password(password, user['password_hash']):
                    SHIELD.record_auth_failure(ip, email)
                    self.send_json(401, {'error': 'Correo o contraseña incorrectos.'})
                    return
                SHIELD.clear_auth_failures(ip, email)
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
            identifier = (body.get('identifier') or '').strip().lower()[:120]
            pin = str(body.get('staff_pin') or '').strip()[:32]
            if not identifier or not pin:
                self.send_json(400, {'error': 'Ingresa el correo o link de la tienda y el PIN de Empleado.'})
                return
            wait_s = SHIELD.is_locked_out(ip, f"staff:{identifier}")
            if wait_s > 0:
                self.send_json(429, {'error': f'Demasiados intentos de PIN. Aguarda {wait_s}s.'})
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
                    SHIELD.record_auth_failure(ip, f"staff:{identifier}")
                    self.send_json(401, {'error': 'Tienda o PIN de Empleado incorrecto.'})
                    return
                SHIELD.clear_auth_failures(ip, f"staff:{identifier}")
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
            if not SHIELD.check_rate('email_otp', ip, limit=5, window_sec=300):
                self.send_json(429, {'error': 'Espera unos minutos antes de pedir otro código.'})
                return
            email = (body.get('email') or '').strip().lower()[:120]
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
            email = (body.get('email') or '').strip().lower()[:120]
            recovery_pin = str(body.get('recovery_pin') or '').strip()[:32]
            email_code = str(body.get('email_code') or '').strip()[:16]
            new_password = str(body.get('new_password') or '')

            wait_s = SHIELD.is_locked_out(ip, f"reset:{email}")
            if wait_s > 0:
                self.send_json(429, {'error': f'Por seguridad anti-fuerza bruta, espera {wait_s}s antes de intentar de nuevo.'})
                return

            if not email or len(new_password) < 4:
                self.send_json(400, {'error': 'Ingresa tu correo y una nueva contraseña de al menos 4 caracteres.'})
                return

            conn = get_db()
            try:
                user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
                if not user:
                    SHIELD.record_auth_failure(ip, f"reset:{email}")
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
                    SHIELD.record_auth_failure(ip, f"reset:{email}")
                    if not user['recovery_pin_hash']:
                        self.send_json(400, {'error': 'Esta cuenta aún no tenía PIN Secreto configurado.'})
                    else:
                        self.send_json(401, {'error': 'PIN Secreto de Recuperación incorrecto.'})
                    return

                SHIELD.clear_auth_failures(ip, f"reset:{email}")
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

                curr_pw = str(body.get('current_password') or '')
                new_pw = str(body.get('new_password') or '')
                new_pin = str(body.get('recovery_pin') or '').strip()[:32]

                if not verify_password(curr_pw, user['password_hash']):
                    SHIELD.record_auth_failure(ip, user['email'])
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

        if path == '/api/auth/logout-all':
            conn = get_db()
            try:
                user, scope = self.get_session_context(conn)
                if not user or scope == 'staff':
                    self.send_json(403, {'error': 'Acción reservada al titular de la cuenta.'})
                    return
                auth = self.headers.get('Authorization', '')
                curr_tok = auth[7:].strip() if auth.startswith('Bearer ') else ''
                conn.execute('DELETE FROM sessions WHERE user_id = ? AND token != ?', (user['id'], curr_tok))
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

        # Webhook automático por pedido de cada comercio
        if path.startswith('/api/webhooks/mp-order/'):
            try:
                owner_id = int(path.split('/')[-1])
            except Exception:
                self.send_json(200, {'received': True})
                return
            query = parse_qs(parsed.query)
            payment_id = (
                query.get('id', [None])[0]
                or query.get('data.id', [None])[0]
                or (body.get('data') or {}).get('id')
            )
            conn = get_db()
            try:
                prof = conn.execute('SELECT mp_access_token FROM store_profiles WHERE user_id = ?', (owner_id,)).fetchone()
                mp_token = decrypt_secret(prof['mp_access_token'], conn) if prof else ''
                if mp_token and payment_id:
                    code, pdata = mp_api_request('GET', f'/v1/payments/{payment_id}', mp_token)
                    if code == 200 and pdata.get('status') == 'approved':
                        ref = str(pdata.get('external_reference') or '')
                        if ref.startswith('order_'):
                            oid = ref[6:]
                            ord_row = conn.execute('SELECT id, payment_status, timeline_json FROM orders WHERE id = ? AND user_id = ?', (oid, owner_id)).fetchone()
                            if ord_row and ord_row['payment_status'] != 'paid':
                                new_tl = append_timeline_event(ord_row['timeline_json'], 'paid', 'Pago acreditado automáticamente por Mercado Pago', f"Operación #{payment_id}")
                                conn.execute(
                                    "UPDATE orders SET payment_status = 'paid', mp_payment_id = ?, timeline_json = ? WHERE id = ?",
                                    (str(payment_id), new_tl, oid)
                                )
                                conn.commit()
            except Exception as e:
                print("Order MP webhook error:", e)
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
                stock_val = max(0, int(body.get('stock') or 0))
                if variants:
                    stock_val = sum(max(0, int(v.get('stock') or 0)) for v in variants)
                conn.execute(
                    '''INSERT INTO products (id, user_id, name, price, cost_price, category, stock, min_stock, barcode, sku, image_url, variants_json, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (
                        pid, user['id'],
                        (body.get('name') or '').strip()[:140],
                        max(0.0, float(body.get('price') or 0)),
                        max(0.0, float(body.get('cost_price') or 0)),
                        (body.get('category') or 'General').strip()[:60],
                        stock_val,
                        max(0, int(body.get('min_stock') or 3)),
                        (body.get('barcode') or '').strip()[:64],
                        (body.get('sku') or body.get('barcode') or '').strip()[:64],
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

        if path == '/api/products/bulk-price':
            conn = get_db()
            try:
                user, _ = self.require_active_user(conn, owner_only=True)
                if not user:
                    return
                pct = float(body.get('percent') or 0)
                if pct == 0 or pct < -95 or pct > 500:
                    self.send_json(400, {'error': 'Ingresa un porcentaje válido entre -95% y +500%.'})
                    return
                cat = (body.get('category') or 'ALL').strip()
                round_to = max(0, int(body.get('round_to') or 0))
                apply_cost = bool(body.get('apply_to_cost'))

                if cat and cat != 'ALL':
                    prods = conn.execute('SELECT id, price, cost_price FROM products WHERE user_id = ? AND category = ?', (user['id'], cat)).fetchall()
                else:
                    prods = conn.execute('SELECT id, price, cost_price FROM products WHERE user_id = ?', (user['id'],)).fetchall()

                factor = 1.0 + (pct / 100.0)
                for p in prods:
                    np = max(0.0, float(p['price'] or 0) * factor)
                    nc = max(0.0, float(p['cost_price'] or 0) * factor) if apply_cost else float(p['cost_price'] or 0)
                    if round_to > 1:
                        np = round(np / round_to) * round_to
                        if apply_cost:
                            nc = round(nc / round_to) * round_to
                    else:
                        np = round(np, 2)
                        nc = round(nc, 2)
                    conn.execute('UPDATE products SET price = ?, cost_price = ? WHERE id = ? AND user_id = ?', (np, nc, p['id'], user['id']))
                conn.commit()
                updated_prods = conn.execute('SELECT * FROM products WHERE user_id = ? ORDER BY created_at DESC', (user['id'],)).fetchall()
                self.send_json(200, {'updated_count': len(prods), 'products': [dict(x) for x in updated_prods]})
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
                desc = (body.get('description') or '').strip()[:160]
                amount = float(body.get('amount') or 0)
                if not desc or amount <= 0:
                    self.send_json(400, {'error': 'Ingresa descripción y monto válido del gasto.'})
                    return
                eid = 'exp_' + secrets.token_hex(6)
                now_iso = utc_now().isoformat()
                exp_date = (body.get('expense_date') or now_iso[:10]).strip()[:16]
                conn.execute(
                    '''INSERT INTO expenses (id, user_id, category, description, amount, expense_date, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)''',
                    (eid, user['id'], (body.get('category') or 'Operativo').strip()[:60], desc, amount, exp_date, now_iso)
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
                    '''INSERT INTO customers (id, user_id, name, phone, address, postal_code, city, province, handle, notes, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (
                        cid, user['id'],
                        (body.get('name') or '').strip()[:100],
                        (body.get('phone') or '').strip()[:40],
                        (body.get('address') or '').strip()[:200],
                        (body.get('postal_code') or '').strip()[:16],
                        (body.get('city') or '').strip()[:80],
                        (body.get('province') or '').strip()[:80],
                        (body.get('handle') or '').strip()[:80],
                        (body.get('notes') or '').strip()[:240],
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

                profile = conn.execute('SELECT next_folio_number, tax_rate FROM store_profiles WHERE user_id = ?', (user['id'],)).fetchone()
                folio_num = (profile['next_folio_number'] if profile else 1001)
                folio_str = '#' + str(folio_num).zfill(6)
                oid = 'ord_' + secrets.token_hex(6)
                tracking_code = 'PED-' + secrets.token_hex(3).upper()
                now_iso = utc_now().isoformat()

                cname = (body.get('customer_name') or 'Cliente').strip()[:100]
                cphone = (body.get('customer_phone') or '').strip()[:40]
                caddr = (body.get('customer_address') or '').strip()[:220]
                ccp = (body.get('customer_postal_code') or '').strip()[:16]
                ccity = (body.get('customer_city') or '').strip()[:80]
                cprov = (body.get('customer_province') or '').strip()[:80]
                branch_name = (body.get('branch_name') or '').strip()[:120]
                chandle = (body.get('customer_handle') or '').strip()[:80]
                shipping_cost = max(0.0, float(body.get('shipping_cost') or 0))
                tax_amount = max(0.0, float(body.get('tax_amount') or 0))
                del_raw = body.get('delivery_method') or 'delivery'
                delivery_method = del_raw if del_raw in ('delivery', 'pickup', 'branch') else 'delivery'
                payment_method = (body.get('payment_method') or 'mercadopago').strip()[:32]
                pay_status = 'paid' if body.get('payment_status') == 'paid' else 'pending'

                total_cost = 0.0
                enriched_items = []
                for item in items:
                    pname = (item.get('productName') or '').strip()[:140]
                    base_name = pname.split(' (')[0].strip()
                    variant_sel = (item.get('variantName') or '').strip()[:60]
                    qty = max(1, int(item.get('quantity') or 1))
                    prod = conn.execute(
                        'SELECT id, stock, cost_price, variants_json FROM products WHERE user_id = ? AND (lower(name) = ? OR lower(name) = ?)',
                        (user['id'], pname.lower(), base_name.lower())
                    ).fetchone()
                    unit_cost = float(prod['cost_price']) if prod else max(0.0, float(item.get('unitCost') or 0))
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

                order_total = max(0.0, float(body.get('total') or 0))
                net_profit = (order_total - shipping_cost - tax_amount) - total_cost

                tl_json = append_timeline_event('[]', 'created', 'Pedido registrado en tienda', f"Comprobante {folio_str}")
                if pay_status == 'paid':
                    tl_json = append_timeline_event(tl_json, 'paid', 'Abono confirmado', '')

                conn.execute(
                    '''INSERT INTO orders (
                           id, user_id, tracking_code, folio_number, customer_name, customer_phone,
                           customer_address, customer_postal_code, customer_city, customer_province, branch_name,
                           customer_handle, items_json, subtotal, discount_amount,
                           discount_label, shipping_cost, tax_amount, total, total_cost, net_profit,
                           payment_status, payment_method, delivery_method, dispatch_status, timeline_json, notes, source, created_at
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pos', ?)''',
                    (
                        oid, user['id'], tracking_code, folio_str, cname, cphone,
                        caddr, ccp, ccity, cprov, branch_name, chandle,
                        json.dumps(enriched_items, ensure_ascii=False),
                        max(0.0, float(body.get('subtotal') or 0)),
                        max(0.0, float(body.get('discount_amount') or 0)),
                        (body.get('discount_label') or '')[:80],
                        shipping_cost,
                        tax_amount,
                        order_total,
                        total_cost,
                        net_profit,
                        pay_status,
                        payment_method,
                        delivery_method,
                        body.get('dispatch_status') or 'to_prepare',
                        tl_json,
                        (body.get('notes') or '').strip()[:300],
                        now_iso
                    )
                )

                conn.execute('UPDATE store_profiles SET next_folio_number = ? WHERE user_id = ?', (folio_num + 1, user['id']))
                upsert_customer_record(conn, user['id'], cname, cphone, caddr, chandle, ccp, ccity, cprov, inc_order=True)

                conn.commit()
                order = conn.execute('SELECT * FROM orders WHERE id = ?', (oid,)).fetchone()
                self.send_json(201, {'order': dict(order), 'next_folio_number': folio_num + 1})
            finally:
                conn.close()
            return

        # Anular pedido y devolver automáticamente todo el stock (incluyendo variantes)
        if path.startswith('/api/orders/') and path.endswith('/cancel-restock'):
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
                if order['dispatch_status'] == 'cancelled':
                    self.send_json(400, {'error': 'Este pedido ya fue anulado anteriormente.'})
                    return

                restock_order_items(conn, user['id'], order['items_json'])
                new_tl = append_timeline_event(order['timeline_json'], 'cancelled', 'Pedido anulado y stock devuelto al catálogo', '')
                conn.execute(
                    "UPDATE orders SET dispatch_status = 'cancelled', payment_status = 'cancelled', total = 0, total_cost = 0, net_profit = 0, timeline_json = ? WHERE id = ?",
                    (new_tl, order_id)
                )
                conn.commit()
                updated = conn.execute('SELECT * FROM orders WHERE id = ?', (order_id,)).fetchone()
                prods = conn.execute('SELECT * FROM products WHERE user_id = ? ORDER BY created_at DESC', (user['id'],)).fetchall()
                self.send_json(200, {'order': dict(updated), 'products': [dict(p) for p in prods]})
            finally:
                conn.close()
            return

        # Unificar varios pedidos ("Bolsita abierta" -> un solo paquete y un solo envío)
        if path == '/api/orders/merge':
            conn = get_db()
            try:
                user, _ = self.require_active_user(conn)
                if not user:
                    return
                order_ids = body.get('order_ids') or []
                if not isinstance(order_ids, list) or len(order_ids) < 2:
                    self.send_json(400, {'error': 'Selecciona al menos 2 pedidos para unificarlos en un solo envío.'})
                    return

                rows = []
                for oid in order_ids[:15]:
                    r = conn.execute("SELECT * FROM orders WHERE id = ? AND user_id = ? AND dispatch_status != 'cancelled'", (str(oid), user['id'])).fetchone()
                    if r:
                        rows.append(r)
                if len(rows) < 2:
                    self.send_json(400, {'error': 'No se encontraron pedidos activos válidos para unificar.'})
                    return

                primary = rows[0]
                absorbed = rows[1:]
                merged_items = []
                for r in rows:
                    try:
                        its = json.loads(r['items_json'] or '[]')
                    except Exception:
                        its = []
                    merged_items.extend(its)

                new_subtotal = sum(float(r['subtotal'] or 0) for r in rows)
                new_disc = sum(float(r['discount_amount'] or 0) for r in rows)
                # Cobra UN SOLO envío (el mayor entre los pedidos combinados)
                new_ship = max(float(r['shipping_cost'] or 0) for r in rows)
                new_tax = sum(float(r['tax_amount'] or 0) for r in rows)
                new_cost = sum(float(r['total_cost'] or 0) for r in rows)
                new_total = max(0.0, (new_subtotal - new_disc) + new_ship + new_tax)
                new_profit = (new_total - new_ship - new_tax) - new_cost
                all_paid = all(r['payment_status'] == 'paid' for r in rows)
                absorbed_folios = ', '.join(r['folio_number'] for r in absorbed)
                new_tl = append_timeline_event(primary['timeline_json'], 'merged', 'Pedidos unificados en un único envío', f"Sumó: {absorbed_folios}")

                conn.execute(
                    '''UPDATE orders
                       SET items_json = ?, subtotal = ?, discount_amount = ?, shipping_cost = ?,
                           tax_amount = ?, total = ?, total_cost = ?, net_profit = ?,
                           payment_status = ?, mp_payment_link = '', timeline_json = ?
                       WHERE id = ? AND user_id = ?''',
                    (
                        json.dumps(merged_items, ensure_ascii=False),
                        new_subtotal, new_disc, new_ship, new_tax, new_total, new_cost, new_profit,
                        'paid' if all_paid else 'pending', new_tl, primary['id'], user['id']
                    )
                )
                for r in absorbed:
                    conn.execute('DELETE FROM orders WHERE id = ? AND user_id = ?', (r['id'], user['id']))
                conn.commit()

                all_orders = conn.execute('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 300', (user['id'],)).fetchall()
                self.send_json(200, {'merged_order_id': primary['id'], 'orders': [dict(o) for o in all_orders]})
            finally:
                conn.close()
            return

        # Autogestión del comprador en seguimiento.html: completar/corregir dirección y CP para Correo Argentino
        if path.startswith('/api/public/track/') and path.endswith('/update-address'):
            if not SHIELD.check_rate('track_addr', ip, limit=10, window_sec=60):
                self.send_json(429, {'error': 'Demasiados intentos. Aguarda un minuto.'})
                return
            tcode = re.sub(r'[^A-Z0-9\-]', '', path.split('/')[4].strip().upper())[:24]
            conn = get_db()
            try:
                order = conn.execute('SELECT * FROM orders WHERE tracking_code = ?', (tcode,)).fetchone()
                if not order:
                    self.send_json(404, {'error': 'Pedido no encontrado'})
                    return
                if order['dispatch_status'] in ('dispatched', 'delivered', 'cancelled'):
                    self.send_json(400, {'error': 'El paquete ya salió a despacho y no admite cambio de domicilio.'})
                    return

                caddr = (body.get('customer_address') or '').strip()[:220]
                ccp = (body.get('customer_postal_code') or '').strip()[:16]
                ccity = (body.get('customer_city') or '').strip()[:80]
                cprov = (body.get('customer_province') or '').strip()[:80]
                branch = (body.get('branch_name') or '').strip()[:120]
                cphone = (body.get('customer_phone') or order['customer_phone'] or '').strip()[:40]
                del_mode = body.get('delivery_method') or order['delivery_method'] or 'delivery'
                if del_mode not in ('delivery', 'branch', 'pickup'):
                    del_mode = 'delivery'

                if del_mode == 'delivery' and (not caddr or not ccp):
                    self.send_json(400, {'error': 'Completa calle/altura y Código Postal para el envío.'})
                    return

                full_display_addr = ', '.join(x for x in [caddr, ccity, cprov, f"CP {ccp}" if ccp else ''] if x) or order['customer_address']
                if del_mode == 'branch' and branch:
                    full_display_addr = f"Sucursal Correo: {branch}" + (f" (CP {ccp} - {cprov})" if ccp or cprov else '')

                new_tl = append_timeline_event(order['timeline_json'], 'address_updated', 'Datos de envío y CP confirmados por el cliente', full_display_addr)
                conn.execute(
                    '''UPDATE orders
                       SET customer_address = ?, customer_postal_code = ?, customer_city = ?,
                           customer_province = ?, branch_name = ?, customer_phone = ?,
                           delivery_method = ?, timeline_json = ?
                       WHERE id = ?''',
                    (full_display_addr, ccp, ccity, cprov, branch, cphone, del_mode, new_tl, order['id'])
                )
                upsert_customer_record(conn, order['user_id'], order['customer_name'], cphone, full_display_addr, order['customer_handle'], ccp, ccity, cprov, inc_order=False)
                conn.commit()
                self.send_json(200, {'ok': True, 'customer_address': full_display_addr})
            finally:
                conn.close()
            return

        # Autogestión del comprador en seguimiento.html: subir comprobante de transferencia bancaria
        if path.startswith('/api/public/track/') and path.endswith('/upload-proof'):
            if not SHIELD.check_rate('track_proof', ip, limit=6, window_sec=60):
                self.send_json(429, {'error': 'Demasiados intentos. Aguarda un minuto.'})
                return
            tcode = re.sub(r'[^A-Z0-9\-]', '', path.split('/')[4].strip().upper())[:24]
            proof_data = str(body.get('proof_data_url') or '').strip()
            ref_txt = (body.get('transfer_reference') or '').strip()[:120]
            if not proof_data.startswith('data:image/') or len(proof_data) > 950_000:
                self.send_json(400, {'error': 'Adjunta una imagen válida del comprobante.'})
                return
            conn = get_db()
            try:
                order = conn.execute('SELECT * FROM orders WHERE tracking_code = ?', (tcode,)).fetchone()
                if not order:
                    self.send_json(404, {'error': 'Pedido no encontrado'})
                    return
                new_tl = append_timeline_event(order['timeline_json'], 'proof_uploaded', 'Comprobante de transferencia adjuntado por el cliente', ref_txt or 'En revisión por la tienda')
                conn.execute(
                    "UPDATE orders SET transfer_proof_url = ?, transfer_reference = ?, payment_method = 'transfer', timeline_json = ? WHERE id = ?",
                    (proof_data, ref_txt, new_tl, order['id'])
                )
                conn.commit()
                self.send_json(200, {'ok': True})
            finally:
                conn.close()
            return

        # Confirmación de recepción del paquete por el comprador
        if path.startswith('/api/public/track/') and path.endswith('/confirm-received'):
            if not SHIELD.check_rate('track_recv', ip, limit=6, window_sec=60):
                self.send_json(429, {'error': 'Aguarda unos segundos.'})
                return
            tcode = re.sub(r'[^A-Z0-9\-]', '', path.split('/')[4].strip().upper())[:24]
            conn = get_db()
            try:
                order = conn.execute('SELECT * FROM orders WHERE tracking_code = ?', (tcode,)).fetchone()
                if not order:
                    self.send_json(404, {'error': 'Pedido no encontrado'})
                    return
                if order['dispatch_status'] == 'dispatched':
                    new_tl = append_timeline_event(order['timeline_json'], 'delivered', 'Recepción del paquete confirmada por el cliente', '¡Entregado con éxito!')
                    conn.execute("UPDATE orders SET dispatch_status = 'delivered', timeline_json = ? WHERE id = ?", (new_tl, order['id']))
                    conn.commit()
                self.send_json(200, {'ok': True})
            finally:
                conn.close()
            return

        if path.startswith('/api/public/store/') and path.endswith('/checkout'):
            if not SHIELD.check_rate('public_checkout', ip, limit=8, window_sec=60):
                self.send_json(429, {'error': 'Demasiados pedidos seguidos desde esta conexión. Aguarda un minuto.'})
                return
            if (body.get('website_hp') or '').strip():
                self.send_json(400, {'error': 'Solicitud bloqueada por filtro anti-bots.'})
                return

            slug = re.sub(r'[^a-z0-9\-]', '', path.split('/')[4].strip().lower())[:64]
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
                cname = (body.get('customer_name') or '').strip()[:100]
                cphone = (body.get('customer_phone') or '').strip()[:40]
                raw_del = body.get('delivery_method') or 'delivery'
                if raw_del == 'pickup' and bool(profile['allow_pickup']):
                    delivery_method = 'pickup'
                elif raw_del == 'branch' and float(profile['shipping_branch_rate'] or 0) > 0:
                    delivery_method = 'branch'
                else:
                    delivery_method = 'delivery'

                cstreet = (body.get('customer_address') or '').strip()[:180]
                ccp = (body.get('customer_postal_code') or '').strip()[:16]
                ccity = (body.get('customer_city') or '').strip()[:80]
                cprov = (body.get('customer_province') or '').strip()[:80]
                branch_name = (body.get('branch_name') or '').strip()[:120]

                if delivery_method == 'pickup':
                    caddr = cstreet or 'Retiro en Local / Punto de Entrega'
                elif delivery_method == 'branch':
                    caddr = f"Sucursal Correo: {branch_name or ccity}" + (f" (CP {ccp} - {cprov})" if ccp or cprov else '')
                else:
                    caddr = ', '.join(x for x in [cstreet, ccity, cprov, f"CP {ccp}" if ccp else ''] if x)

                notes = (body.get('notes') or '').strip()[:300]
                payment_method = (body.get('payment_method') or 'mercadopago').strip()[:32]

                if not cname or not cphone or not req_items or len(req_items) > 60:
                    self.send_json(400, {'error': 'Completa tu nombre, WhatsApp y al menos un producto.'})
                    return

                enriched_items = []
                subtotal = 0.0
                total_cost = 0.0

                for ri in req_items:
                    pid = str(ri.get('product_id') or '')[:40]
                    qty = max(1, min(999, int(ri.get('quantity') or 1)))
                    vname = (ri.get('variant_name') or '').strip()[:60]
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

                flat_ship = float(profile['shipping_flat_rate'] or 0)
                branch_ship = float(profile['shipping_branch_rate'] or 0)
                free_min = float(profile['free_shipping_min'] or 0)
                if delivery_method == 'pickup':
                    shipping_cost = 0.0
                elif free_min > 0 and subtotal >= free_min:
                    shipping_cost = 0.0
                elif delivery_method == 'branch':
                    shipping_cost = max(0.0, branch_ship)
                else:
                    shipping_cost = max(0.0, flat_ship)

                tax_rate = max(0.0, float(profile['tax_rate'] or 0))
                tax_amount = round(subtotal * (tax_rate / 100.0), 2) if tax_rate > 0 else 0.0
                grand_total = round(subtotal + shipping_cost + tax_amount, 2)

                folio_num = int(profile['next_folio_number'] or 1001)
                folio_str = '#' + str(folio_num).zfill(6)
                oid = 'ord_' + secrets.token_hex(6)
                tracking_code = 'PED-' + secrets.token_hex(3).upper()
                now_iso = utc_now().isoformat()
                net_profit = subtotal - total_cost

                mp_link = ''
                mp_token = decrypt_secret(profile['mp_access_token'], conn)
                if mp_token:
                    base_url = self.get_base_url(conn)
                    pref_payload = {
                        "items": [{
                            "id": tracking_code,
                            "title": f"Pedido {folio_str} - {profile['name']}",
                            "quantity": 1,
                            "currency_id": resolve_mp_currency(profile),
                            "unit_price": float(grand_total)
                        }],
                        "external_reference": f"order_{oid}",
                        "back_urls": {
                            "success": f"{base_url}/seguimiento.html?code={tracking_code}",
                            "failure": f"{base_url}/seguimiento.html?code={tracking_code}",
                            "pending": f"{base_url}/seguimiento.html?code={tracking_code}"
                        },
                        "auto_return": "approved"
                    }
                    if base_url.startswith('https://'):
                        pref_payload["notification_url"] = f"{base_url}/api/webhooks/mp-order/{owner['id']}"
                    try:
                        _, pref = mp_api_request('POST', '/checkout/preferences', mp_token, pref_payload)
                        mp_link = pref.get('init_point') or pref.get('sandbox_init_point') or ''
                    except Exception:
                        mp_link = ''

                tl_json = append_timeline_event('[]', 'created', 'Pedido recibido desde Tienda Online', f"Folio {folio_str}")

                conn.execute(
                    '''INSERT INTO orders (
                           id, user_id, tracking_code, folio_number, customer_name, customer_phone,
                           customer_address, customer_postal_code, customer_city, customer_province, branch_name,
                           customer_handle, items_json, subtotal, discount_amount,
                           discount_label, shipping_cost, tax_amount, total, total_cost, net_profit,
                           payment_status, payment_method, mp_payment_link, delivery_method,
                           dispatch_status, timeline_json, notes, source, created_at
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?, 0, '', ?, ?, ?, ?, ?, 'pending', ?, ?, ?, 'to_prepare', ?, ?, 'web_store', ?)''',
                    (
                        oid, owner['id'], tracking_code, folio_str, cname, cphone,
                        caddr, ccp, ccity, cprov, branch_name,
                        json.dumps(enriched_items, ensure_ascii=False),
                        subtotal, shipping_cost, tax_amount, grand_total, total_cost, net_profit,
                        payment_method, mp_link, delivery_method, tl_json, notes, now_iso
                    )
                )
                conn.execute('UPDATE store_profiles SET next_folio_number = ? WHERE user_id = ?', (folio_num + 1, owner['id']))
                upsert_customer_record(conn, owner['id'], cname, cphone, caddr, 'Tienda Web', ccp, ccity, cprov, inc_order=True)
                conn.commit()
                self.send_json(201, {
                    'order': {
                        'folio_number': folio_str,
                        'tracking_code': tracking_code,
                        'subtotal': subtotal,
                        'shipping_cost': shipping_cost,
                        'tax_amount': tax_amount,
                        'total': grand_total
                    },
                    'payment_link': mp_link,
                    'external_pay_link': profile['external_pay_link'] or '',
                    'bank_alias': profile['bank_alias'] or '',
                    'bank_holder': profile['bank_holder'] or '',
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
                profile = conn.execute('SELECT * FROM store_profiles WHERE user_id = ?', (user['id'],)).fetchone()
                mp_token = decrypt_secret(profile['mp_access_token'], conn) if profile else ''
                if not mp_token:
                    if profile and profile['external_pay_link']:
                        self.send_json(200, {'payment_link': profile['external_pay_link'], 'mode': 'external'})
                        return
                    self.send_json(400, {'error': 'Configura primero tu Access Token de Mercado Pago en Cobros MP.'})
                    return

                base_url = self.get_base_url(conn)
                pref_payload = {
                    "items": [
                        {
                            "id": order['tracking_code'],
                            "title": f"Pedido {order['folio_number']} - {profile['name']}",
                            "quantity": 1,
                            "currency_id": resolve_mp_currency(profile),
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
                if base_url.startswith('https://'):
                    pref_payload["notification_url"] = f"{base_url}/api/webhooks/mp-order/{user['id']}"
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

        if not self.check_global_shield(path):
            return

        try:
            body = self.read_json_body()
        except PayloadTooLargeError:
            self.send_json(413, {'error': 'El tamaño de la solicitud supera el límite permitido.'})
            return

        if path == '/api/store/profile':
            conn = get_db()
            try:
                user, _ = self.require_active_user(conn, owner_only=True)
                if not user:
                    return
                if 'slug' in body and str(body['slug']).strip():
                    body['slug'] = ensure_unique_slug(conn, str(body['slug']), user['id'])

                if body.get('clear_mp_token') is True:
                    body['mp_access_token'] = ''
                elif 'mp_access_token' in body:
                    tok = str(body['mp_access_token'] or '').strip()
                    if tok:
                        body['mp_access_token'] = encrypt_secret(tok, conn)
                    else:
                        del body['mp_access_token']

                fields = [
                    'name', 'slug', 'store_icon', 'logo_data_url', 'receipt_theme', 'app_palette',
                    'custom_color', 'business_mode', 'phone', 'address', 'origin_postal_code', 'origin_province',
                    'instagram', 'website', 'country_code', 'currency_code', 'currency_symbol',
                    'tax_label', 'tax_rate', 'bank_alias', 'bank_holder', 'external_pay_link',
                    'cash_on_delivery', 'shipping_flat_rate', 'shipping_branch_rate', 'free_shipping_min',
                    'allow_pickup', 'next_folio_number', 'receipt_footer_message', 'mp_access_token',
                    'staff_pin', 'voice_accent', 'voice_template'
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
                        conn.execute('UPDATE users SET store_name = ? WHERE id = ?', (str(body['name'])[:80], user['id']))
                    conn.commit()
                profile = conn.execute('SELECT * FROM store_profiles WHERE user_id = ?', (user['id'],)).fetchone()
                self.send_json(200, {'profile': sanitize_profile_for_client(profile, conn, is_staff=False)})
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
                stock_val = max(0, int(body.get('stock') or 0))
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
                        (body.get('name') or '').strip()[:140],
                        max(0.0, float(body.get('price') or 0)),
                        max(0.0, float(body.get('cost_price') or 0)),
                        (body.get('category') or 'General').strip()[:60],
                        stock_val,
                        max(0, int(body.get('min_stock') or 3)),
                        (body.get('barcode') or '').strip()[:64],
                        (body.get('barcode') or '').strip()[:64],
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

        if not self.check_global_shield(path):
            return

        try:
            body = self.read_json_body()
        except PayloadTooLargeError:
            self.send_json(413, {'error': 'Solicitud demasiado grande.'})
            return

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
                existing = conn.execute('SELECT * FROM orders WHERE id = ? AND user_id = ?', (oid, user['id'])).fetchone()
                if not existing:
                    self.send_json(404, {'error': 'Pedido no encontrado'})
                    return

                tl_json = existing['timeline_json'] or '[]'
                if 'payment_status' in body and body['payment_status'] == 'paid' and existing['payment_status'] != 'paid':
                    tl_json = append_timeline_event(tl_json, 'paid', 'Abono verificado y aprobado por la tienda', '')
                if 'dispatch_status' in body and body['dispatch_status'] != existing['dispatch_status']:
                    st = body['dispatch_status']
                    carrier = str(body.get('shipping_carrier') or existing['shipping_carrier'] or '').strip()
                    trk = str(body.get('shipping_tracking') or existing['shipping_tracking'] or '').strip()
                    if st == 'packed':
                        tl_json = append_timeline_event(tl_json, 'packed', 'Paquete preparado y empacado', 'Listo para despacho')
                    elif st == 'dispatched':
                        det = ' — '.join(x for x in [carrier, f"Guía: {trk}" if trk else ''] if x)
                        tl_json = append_timeline_event(tl_json, 'dispatched', 'Paquete despachado en correo / transporte', det)
                    elif st == 'delivered':
                        tl_json = append_timeline_event(tl_json, 'delivered', 'Paquete entregado', '')

                allowed = [
                    'payment_status', 'dispatch_status', 'shipping_carrier', 'shipping_tracking',
                    'customer_address', 'customer_postal_code', 'customer_city', 'customer_province', 'branch_name', 'notes'
                ]
                set_clauses = ['timeline_json = ?']
                values = [tl_json]
                for f in allowed:
                    if f in body:
                        set_clauses.append(f"{f} = ?")
                        values.append(str(body[f])[:220])
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

        if not self.check_global_shield(path):
            return

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
        print("=" * 66)
        print(f"[OK] VENTAFLOW POS SaaS v5.0 AUTOPILOT ACTIVO en http://localhost:{PORT}")
        print("Motor DB:", "PostgreSQL (ThreadedPool)" if IS_POSTGRES else f"SQLite WAL ({DB_PATH})")
        print("=" * 66)
        httpd.serve_forever()


if __name__ == "__main__":
    run()
