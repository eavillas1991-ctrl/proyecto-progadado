/* ============================================================
   ProGanado — Autenticación local compatible con file://
   ============================================================ */
'use strict';

const AUTH_KEY = 'proGanadoAuth_v2';
const $a = sel => document.querySelector(sel);
const MAX_ADMINS = 4;
const MAX_USUARIOS = 7;
const DIAS_SESION = 7;

const AUTH_DEFAULT = [
  { correo: 'eavillas1991@gmail.com', pass: 'ProGanado2026*', nombre: 'Emilio', role: 'admin' },
  { correo: 'eavillas1991+admin2@gmail.com', pass: 'Farma2026*9', nombre: 'Administrador 2', role: 'admin' },
  { correo: 'eavillas1991+usuario1@gmail.com', pass: 'Ordeño2026*3', nombre: 'Usuario 1', role: 'usuario' }
];

const ES_CORREO = v => /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/.test(String(v || '').trim().toLowerCase());

// Algoritmo de hash de respaldo compatible con entornos locales file://
async function sha256(texto) {
  if (window.crypto && window.crypto.subtle) {
    try {
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(texto));
      return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (e) {}
  }
  // Hash ligero para modo local directo
  let hash = 0;
  for (let i = 0; i < texto.length; i++) {
    hash = (hash << 5) - hash + texto.charCodeAt(i);
    hash |= 0;
  }
  return 'local_' + Math.abs(hash).toString(16);
}

let auth = null;

function authSave() { 
  try { localStorage.setItem(AUTH_KEY, JSON.stringify(auth)); } catch (e) {} 
}

async function authLoad() {
  auth = { usuarios: [] };
  for (const def of AUTH_DEFAULT) {
    const hash = await sha256(def.pass);
    auth.usuarios.push({
      user: def.correo.toLowerCase(),
      correo: def.correo.toLowerCase(),
      nombre: def.nombre,
      role: def.role,
      hash: hash,
      ultimoAcceso: null
    });
  }
  authSave();
}

function sesionActual() {
  try { return JSON.parse(sessionStorage.getItem('proGanadoSesion')); } catch (e) { return null; }
}

function codigoLocal(correo) {
  const c = String(Math.floor(100000 + Math.random() * 900000));
  sessionStorage.setItem('proGanadoCodigoLocal', JSON.stringify({ 
    correo: String(correo).toLowerCase(), 
    codigo: c, 
    exp: Date.now() + 5 * 60000 
  }));
  return c;
}

function verificarCodigoLocal(correo, codigo) {
  try {
    const r = JSON.parse(sessionStorage.getItem('proGanadoCodigoLocal'));
    if (!r || r.correo !== String(correo).toLowerCase()) return { ok: false, msg: 'Solicita un nuevo código.' };
    if (String(codigo).trim() !== r.codigo) return { ok: false, msg: 'Código incorrecto.' };
    return { ok: true };
  } catch (e) { return { ok: false, msg: 'Error de validación.' }; }
}

let pasoActual = 'credenciales';
let pendiente = null;

function initAuth() {
  const formLogin = $a('#formLogin');
  if (!formLogin) return;

  formLogin.addEventListener('submit', async ev => {
    ev.preventDefault();
    const btn = $a('#btnLogin');
    const msgEl = $a('#loginMsg');

    if (pasoActual === 'credenciales') {
      const userIn = String($a('#loginUser').value).trim().toLowerCase();
      const passIn = String($a('#loginPass').value).trim();

      if (!ES_CORREO(userIn)) { msgEl.textContent = 'Ingresa tu correo completo.'; return; }
      if (!passIn) { msgEl.textContent = 'Ingresa tu contraseña.'; return; }

      btn.disabled = true;
      btn.textContent = 'Verificando…';

      const hashIngresado = await sha256(passIn);
      const u = auth.usuarios.find(x => x.user === userIn);

      btn.disabled = false;
      btn.textContent = 'Entrar';

      if (!u || u.hash !== hashIngresado) {
        msgEl.textContent = 'Correo o contraseña incorrectos.';
        return;
      }

      pendiente = u;
      pasoActual = 'codigo';

      $a('#pasoCredenciales').style.display = 'none';
      $a('#pasoCodigo').style.display = 'block';

      const cLocal = codigoLocal(u.correo);
      const aviso = $a('#modoPruebaAviso');
      if (aviso) {
        aviso.style.display = 'block';
        aviso.innerHTML = 'Tu código de acceso es: <b style="font-size: 16px; color: #1e3a29;">' + cLocal + '</b>';
      }
      msgEl.textContent = '';
    } else {
      const codigoIn = String($a('#loginCodigo').value).trim();
      const val = verificarCodigoLocal(pendiente.correo, codigoIn);

      if (!val.ok) {
        msgEl.textContent = val.msg;
        return;
      }

      const sesion = { user: pendiente.user, nombre: pendiente.nombre, role: pendiente.role, expira: Date.now() + DIAS_SESION * 86400000 };
      sessionStorage.setItem('proGanadoSesion', JSON.stringify(sesion));

      document.body.classList.remove('modo-login');
      $a('#loginView').style.display = 'none';
      $a('.app-shell').style.display = 'block';
    }
  });
}

(async function authBoot() {
  await authLoad();
  initAuth();
})();