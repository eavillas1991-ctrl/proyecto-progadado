# -*- coding: utf-8 -*-
"""
ProGanado — Servidor local
Sirve la página web y envía los códigos de seguridad al correo (2FA).

Uso:  python servidor.py   (o doble click en "Iniciar ProGanado.bat")
Puerto: 8899  →  http://127.0.0.1:8899/index.html

Configuración del correo: archivo correo_config.json (junto a este archivo).
Mientras la contraseña de aplicación no esté configurada, el servidor corre
en MODO PRUEBA: muestra el código en pantalla en vez de enviarlo por correo.
"""
import json
import os
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
CODIGO_VIDA = 5 * 60  # segundos
MAX_INTENTOS_CODIGO = 3

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
        super().end_headers()

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
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n).decode("utf-8")) if n else {}
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

        codigo = generar_codigo()
        cfg = recargar_config()
        if cfg is None:
            # MODO PRUEBA: sin Gmail configurado → código visible en pantalla y consola
            with CODIGOS_LOCK:
                CODIGOS[correo] = {"codigo": codigo, "exp": time.time() + CODIGO_VIDA, "intentos": 0}
            print("    [MODO PRUEBA] código para %s: %s" % (correo, codigo))
            return self._json({"ok": True, "modo_prueba": True, "codigo_prueba": codigo,
                               "msg": "Servidor sin Gmail configurado: modo prueba."})
        try:
            enviar_codigo_gmail(correo, codigo)
        except Exception as e:
            print("    [ERROR Gmail] %s" % e)
            return self._json({"ok": False, "msg": "No se pudo enviar el correo. Revisa correo_config.json."}, 500)
        with CODIGOS_LOCK:
            CODIGOS[correo] = {"codigo": codigo, "exp": time.time() + CODIGO_VIDA, "intentos": 0}
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
            if codigo != reg["codigo"]:
                reg["intentos"] += 1
                return self._json({"ok": False, "msg": "Código incorrecto."}, 400)
            del CODIGOS[correo]  # un solo uso
        return self._json({"ok": True})

# ------------------------------------------------------------------ arranque
if __name__ == "__main__":
    os.chdir(ROOT)
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Manejador)
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
