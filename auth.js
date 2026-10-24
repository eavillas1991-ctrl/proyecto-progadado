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

// Muestra el panel principal y oculta la ventana de login.
function entrar(sesion) {
  const chipNombre = $a('#chipNombre');
  const chipRol = $a('#chipRol');
  const perfil = $a('#perfilChip');

  if (chipNombre) chipNombre.textContent = sesion.nombre || sesion.user;
  if (chipRol) chipRol.textContent = (sesion.role === 'admin' ? 'Administrador' : 'Usuario').toUpperCase();
  if (perfil) {
    const partes = String(sesion.nombre || sesion.user).trim().split(/\s+/);
    perfil.textContent = partes.length > 1
      ? (partes[0][0] + partes[1][0]).toUpperCase()
      : (partes[0] || '?').slice(0, 2).toUpperCase();
  }

  document.body.classList.remove('modo-login');
  $a('#loginView').style.display = 'none';
  // '' deja que styles.css aplique su grid (245px + 1fr); 'block' rompería el sidebar.
  const shell = $a('.app-shell');
  if (shell) shell.style.display = '';
}

function salir() {
  try { sessionStorage.removeItem('proGanadoSesion'); } catch (e) {}
  const form = $a('#formLogin');
  if (form) form.reset();
  const msg = $a('#loginMsg');
  if (msg) msg.textContent = '';
  document.body.classList.add('modo-login');
  $a('#loginView').style.display = '';
}

function initAuth() {
  const formLogin = $a('#formLogin');
  if (!formLogin) return;

  formLogin.addEventListener('submit', async ev => {
    ev.preventDefault();
    const btn = $a('#btnLogin');
    const msgEl = $a('#loginMsg');

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

    const sesion = { user: u.user, nombre: u.nombre, role: u.role, expira: Date.now() + DIAS_SESION * 86400000 };
    sessionStorage.setItem('proGanadoSesion', JSON.stringify(sesion));
    entrar(sesion);
  });
}

(async function authBoot() {
  await authLoad();
  initAuth();

  const btnSalir = $a('#btnLogout');
  if (btnSalir) btnSalir.addEventListener('click', ev => { ev.preventDefault(); salir(); });

  // Si la sesión sigue vigente, entramos directo sin pedir la contraseña.
  const sesion = sesionActual();
  if (sesion && sesion.expira && sesion.expira > Date.now()) {
    entrar(sesion);
  } else {
    document.body.classList.add('modo-login');
  }
})();