# -*- coding: utf-8 -*-
"""
ProGanado — Servidor local
Sirve la página web y envía los códigos de seguridad al correo (2FA).

Uso:  python servidor.py   (o doble click en "Iniciar ProGanado.bat")
Puerto: 8899  →  http://127.0.0.1:8899/index.html

Configuración del correo: archivo correo_config.json (junto a este archivo,
creado a partir de correo_config.example.json).
Mientras la contraseña de aplicación no esté configurada, el servidor corre
en MODO PRUEBA: muestra el código en pantalla en vez de enviarlo por correo.
"""
import hmac
import json
import os
import sqlite3
import re
import smtplib
import ssl
import threading
import time
from email.message import EmailMessage
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(ROOT, "correo_config.json")
PORT = 8899

# ------------------------------------------------------------ base de datos
# Los datos viven en datos/proganado.sqlite3 (carpeta fuera del alcance de la web).
DATA_DIR = os.path.join(ROOT, "datos")
DB_FILE = os.path.join(DATA_DIR, "proganado.sqlite3")
DB_LOCK = threading.Lock()
MAX_BYTES_DB = 50 * 1024 * 1024
MAX_BYTES_FOTO = 15 * 1024 * 1024
MAX_BYTES_JSON = 64 * 1024

def _conexion():
    os.makedirs(DATA_DIR, exist_ok=True)
    con = sqlite3.connect(DB_FILE, check_same_thread=False, timeout=10)
    con.execute("CREATE TABLE IF NOT EXISTS kv (clave TEXT PRIMARY KEY, valor TEXT NOT NULL, actualizado REAL NOT NULL)")
    con.execute("CREATE TABLE IF NOT EXISTS facturas (id TEXT PRIMARY KEY, datos BLOB NOT NULL, actualizado REAL NOT NULL)")
    con.commit()
    return con

# ------------------------------------------------------------------ config
def cargar_config():
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            cfg = json.load(f)
        correo = (cfg.get("correo") or "").strip()
        clave = (cfg.get("clave_aplicacion") or "").replace(" ", "")
        if "@" in correo and len(clave) >= 16 and not clave.upper().startswith("PEGAR"):
            return {"correo": correo, "clave": clave, "de": cfg.get("asistente") or ("ProGanado <%s>" % correo)}
    except FileNotFoundError:
        pass
    return None  # sin configurar → MODO PRUEBA

CONFIG = cargar_config()
CFG_LOCK = threading.Lock()

# ------------------------------------------- códigos activos (en memoria)
CODIGOS = {}          # correo -> {"codigo": str, "exp": float, "intentos": int}
CODIGOS_LOCK = threading.Lock()
CODIGO_VIDA = 5 * 60       # segundos
MAX_INTENTOS_CODIGO = 3
REENVIO_SEGUNDOS = 20      # espera mínima entre envíos al mismo correo

def recargar_config():
    """Permite cambiar la configuración sin reiniciar el servidor."""
    global CONFIG
    with CFG_LOCK:
        CONFIG = cargar_config()
    return CONFIG

def recargar_config_suave():
    # recargar solo si aún no hay config (el usuario acaba de editar el json)
    if CONFIG is None:
        recargar_config()

def generar_codigo():
    return "%06d" % (int.from_bytes(os.urandom(3), "big") % 1000000)

def enviar_codigo_gmail(destino, codigo):
    cfg = recargar_config()
    if cfg is None:
        return False
    msg = EmailMessage()
    msg["From"] = cfg["de"]
    msg["To"] = destino
    msg["Subject"] = "Código de acceso ProGanado: %s" % codigo
    cuerpo = (
        "Tu código de seguridad para ingresar a ProGanado es:\n\n"
        "        %s\n\n"
        "Expira en 5 minutos. Si no solicitaste este código, ignora este correo.\n\n"
        "— Sistema de seguridad ProGanado"
    ) % codigo
    msg.set_content(cuerpo)
    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ctx, timeout=20) as s:
        s.login(cfg["correo"], cfg["clave"])
        s.send_message(msg)
    return True

# ------------------------------------------------------------------ handler
class Manejador(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=ROOT, **kw)

    def end_headers(self):
        # sin caché: evita ver versiones viejas de la página al cambiar código
        self.send_header("Cache-Control", "no-store, must-revalidate")
        # cabeceras de seguridad para todo lo que entrega el servidor
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "img-src 'self' data: blob:; font-src 'self'; object-src 'none'; "
                         "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        super().end_headers()

    # Archivos del servidor y de configuración que nunca se entregan al navegador
    EXT_BLOQUEADAS = (".py", ".pyc", ".json", ".bat", ".md", ".db", ".db-shm", ".db-wal", ".sqlite3", ".sqlite")

    def _ruta_bloqueada(self):
        from urllib.parse import urlsplit, unquote
        ruta = unquote(urlsplit(self.path).path).lower()
        partes = [p for p in ruta.split("/") if p]
        if any(p.startswith(".") for p in partes):      # carpetas/archivos ocultos
            return True
        if any(p in ("__pycache__", "datos") for p in partes):  # caché de Python y base de datos
            return True
        return ruta.endswith(self.EXT_BLOQUEADAS)

    def list_directory(self, path):
        # Sin listados de carpetas: solo se sirven archivos concretos.
        self.send_error(404, "No encontrado")
        return None

    def do_GET(self):
        if self.path.startswith("/api/"):
            return self._api("GET")
        if self._ruta_bloqueada():
            return self.send_error(404, "No encontrado")
        return super().do_GET()

    def do_PUT(self):
        if self.path.startswith("/api/"):
            return self._api("PUT")
        return self.send_error(404, "No encontrado")

    def do_DELETE(self):
        if self.path.startswith("/api/"):
            return self._api("DELETE")
        return self.send_error(404, "No encontrado")

    # ---------------- API de datos (solo 127.0.0.1) ----------------
    def _leer_bytes(self, limite):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n <= 0 or n > limite:
            return None
        return self.rfile.read(n)

    def _api(self, metodo):
        from urllib.parse import urlsplit, unquote
        ruta = unquote(urlsplit(self.path).path)
        try:
            if ruta == "/api/db" and metodo == "GET":
                with DB_LOCK, _conexion() as con:
                    fila = con.execute("SELECT valor, actualizado FROM kv WHERE clave='db'").fetchone()
                if not fila:
                    return self._json({"data": None})
                return self._json({"data": json.loads(fila[0]), "actualizado": fila[1]})

            if ruta == "/api/db" and metodo == "PUT":
                cuerpo = self._leer_bytes(MAX_BYTES_DB)
                if cuerpo is None:
                    return self._json({"ok": False, "msg": "Datos vacíos o demasiado grandes."}, 413)
                texto = cuerpo.decode("utf-8")
                json.loads(texto)  # valida que sea JSON
                with DB_LOCK, _conexion() as con:
                    con.execute("INSERT INTO kv (clave, valor, actualizado) VALUES ('db', ?, ?) "
                                "ON CONFLICT(clave) DO UPDATE SET valor=excluded.valor, actualizado=excluded.actualizado",
                                (texto, time.time()))
                return self._json({"ok": True})

            m = re.match(r"^/api/factura/([A-Za-z0-9_\-]{1,80})$", ruta)
            if m:
                fid = m.group(1)
                if metodo == "GET":
                    with DB_LOCK, _conexion() as con:
                        fila = con.execute("SELECT datos FROM facturas WHERE id=?", (fid,)).fetchone()
                    if not fila:
                        return self._json({"ok": False, "msg": "No encontrada"}, 404)
                    data = bytes(fila[0])
                    self.send_response(200)
                    self.send_header("Content-Type", "image/jpeg")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                if metodo == "PUT":
                    cuerpo = self._leer_bytes(MAX_BYTES_FOTO)
                    if cuerpo is None:
                        return self._json({"ok": False, "msg": "Foto vacía o demasiado grande."}, 413)
                    with DB_LOCK, _conexion() as con:
                        con.execute("INSERT INTO facturas (id, datos, actualizado) VALUES (?, ?, ?) "
                                    "ON CONFLICT(id) DO UPDATE SET datos=excluded.datos, actualizado=excluded.actualizado",
                                    (fid, sqlite3.Binary(cuerpo), time.time()))
                    return self._json({"ok": True})
                if metodo == "DELETE":
                    with DB_LOCK, _conexion() as con:
                        con.execute("DELETE FROM facturas WHERE id=?", (fid,))
                    return self._json({"ok": True})

            return self._json({"ok": False, "msg": "Ruta no encontrada"}, 404)
        except Exception as e:
            print("    [API ERROR] %s" % e)
            return self._json({"ok": False, "msg": "Error del servidor"}, 500)

    def do_HEAD(self):
        if self._ruta_bloqueada():
            return self.send_error(404, "No encontrado")
        return super().do_HEAD()

    def log_message(self, fmt, *args):
        print("[servidor] " + (fmt % args))

    # ---------------- utilidades JSON ----------------
    def _json(self, obj, code=200):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _leer_json(self):
        try:
            cuerpo = self._leer_bytes(MAX_BYTES_JSON)
            return json.loads(cuerpo.decode("utf-8")) if cuerpo else {}
        except Exception:
            return {}

    # ---------------- API ----------------
    def do_POST(self):
        if self.path == "/api/enviar-codigo":
            return self.api_enviar()
        if self.path == "/api/verificar-codigo":
            return self.api_verificar()
        self._json({"ok": False, "msg": "Ruta no encontrada"}, 404)

    def api_enviar(self):
        recargar_config_suave()
        datos = self._leer_json()
        correo = (datos.get("correo") or "").strip().lower()
        if not re.match(r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$", correo):
            return self._json({"ok": False, "msg": "Correo inválido."}, 400)

        with CODIGOS_LOCK:
            anterior = CODIGOS.get(correo)
            if anterior:
                espera = REENVIO_SEGUNDOS - (time.time() - anterior.get("enviado", 0))
                if espera > 0:
                    return self._json({"ok": False,
                                       "msg": "Espera %d segundos antes de pedir otro código." % int(espera + 0.5)}, 429)

        codigo = generar_codigo()
        cfg = recargar_config()
        if cfg is None:
            # MODO PRUEBA: sin Gmail configurado → código visible en pantalla y consola
            with CODIGOS_LOCK:
                CODIGOS[correo] = {"codigo": codigo, "exp": time.time() + CODIGO_VIDA,
                                   "intentos": 0, "enviado": time.time()}
            print("    [MODO PRUEBA] código para %s: %s" % (correo, codigo))
            return self._json({"ok": True, "modo_prueba": True, "codigo_prueba": codigo,
                               "msg": "Servidor sin Gmail configurado: modo prueba."})
        try:
            enviar_codigo_gmail(correo, codigo)
        except Exception as e:
            print("    [ERROR Gmail] %s" % e)
            return self._json({"ok": False, "msg": "No se pudo enviar el correo. Revisa correo_config.json."}, 500)
        with CODIGOS_LOCK:
            CODIGOS[correo] = {"codigo": codigo, "exp": time.time() + CODIGO_VIDA,
                               "intentos": 0, "enviado": time.time()}
        print("    [Gmail] código enviado a %s" % correo)
        return self._json({"ok": True})

    def api_verificar(self):
        datos = self._leer_json()
        correo = (datos.get("correo") or "").strip().lower()
        codigo = (datos.get("codigo") or "").strip()
        with CODIGOS_LOCK:
            reg = CODIGOS.get(correo)
            if not reg:
                return self._json({"ok": False, "msg": "No hay código activo. Solicita uno nuevo."}, 400)
            if time.time() > reg["exp"]:
                del CODIGOS[correo]
                return self._json({"ok": False, "msg": "El código expiró. Solicita uno nuevo."}, 400)
            if reg["intentos"] >= MAX_INTENTOS_CODIGO:
                del CODIGOS[correo]
                return self._json({"ok": False, "msg": "Demasiados intentos. Solicita un código nuevo."}, 400)
            if not hmac.compare_digest(codigo, reg["codigo"]):
                reg["intentos"] += 1
                return self._json({"ok": False, "msg": "Código incorrecto."}, 400)
            del CODIGOS[correo]  # un solo uso
        return self._json({"ok": True})

class ServidorProGanado(ThreadingHTTPServer):
    # En Windows, SO_REUSEADDR deja que dos servidores escuchen el mismo puerto a la vez
    # y entonces los códigos de seguridad se reparten entre ellos (parece "código incorrecto").
    # Al desactivarlo solo puede correr una instancia de ProGanado.
    allow_reuse_address = False

    def server_bind(self):
        try:
            super().server_bind()
        except OSError:
            print("=" * 60)
            print("  ProGanado ya está abierto en otra ventana.")
            print("  Cierra esa ventana del servidor y vuelve a intentar.")
            print("  (el puerto %d está ocupado)" % PORT)
            print("=" * 60)
            raise SystemExit(1)

# ------------------------------------------------------------------ arranque
if __name__ == "__main__":
    os.chdir(ROOT)
    srv = ServidorProGanado(("127.0.0.1", PORT), Manejador)
    modo = "Gmail ACTIVO (%s)" % CONFIG["correo"] if CONFIG else "MODO PRUEBA (sin correo_config.json válido)"
    print("=" * 60)
    print("  ProGanado servidor  ->  http://127.0.0.1:%d/index.html" % PORT)
    print("  Envío de códigos: %s" % modo)
    print("  Detener: Ctrl+C en esta ventana")
    print("=" * 60)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[servidor] detenido")
