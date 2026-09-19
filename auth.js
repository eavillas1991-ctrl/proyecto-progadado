/* ============================================================
   ProGanado — Autenticación y usuarios
   - Máximo 4 administradores y 7 usuarios (total 11 cuentas)
   - Contraseñas con hash SHA-256 + salt único por usuario
   - Bloqueo temporal tras 5 intentos fallidos (5 minutos)
   - Roles: admin (todo) / usuario (consulta + registrar)
   - Sesión persistente en sessionStorage (expira al cerrar pestaña)
   ============================================================ */
'use strict';

const AUTH_KEY = 'proGanadoAuth_v2'; // v2: el usuario es el correo Gmail
const $a = sel => document.querySelector(sel); // helper propio (el $ global vive en app.js)
const MAX_ADMINS = 4;
const MAX_USUARIOS = 7;
const MAX_INTENTOS = 5;
const MINUTOS_BLOQUEO = 5;
const DIAS_SESION = 7;

/* Cuentas iniciales. El usuario de acceso es el correo Gmail: allí llega
   el código de seguridad. Las cuentas +alias (correo+etiqueta@gmail.com)
   entregan en el mismo buzón de eavillas1991@gmail.com. */
const AUTH_DEFAULT = [
  { correo: 'eavillas1991@gmail.com',        pass: 'ProGanado2026*', nombre: 'Emilio',          role: 'admin',   force: true },
  { correo: 'eavillas1991+admin2@gmail.com', pass: 'Farma2026*9',    nombre: 'Administrador 2', role: 'admin',   force: true },
  { correo: 'eavillas1991+admin3@gmail.com', pass: 'Farma2026*13',   nombre: 'Administrador 3', role: 'admin',   force: true },
  { correo: 'eavillas1991+admin4@gmail.com', pass: 'Farma2026*17',   nombre: 'Administrador 4', role: 'admin',   force: true },
  { correo: 'eavillas1991+usuario1@gmail.com', pass: 'Ordeño2026*3',  nombre: 'Usuario 1',      role: 'usuario', force: true },
  { correo: 'eavillas1991+usuario2@gmail.com', pass: 'Potrero2026*5', nombre: 'Usuario 2',      role: 'usuario', force: true }
];

const ES_CORREO = v => /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/.test(String(v || '').trim().toLowerCase());

/* ---------- Utilidades de seguridad ---------- */
async function sha256(texto) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(texto));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
const nuevoSalt = () => crypto.getRandomValues(new Uint8Array(16));
const saltHex = s => [...s].map(b => b.toString(16).padStart(2, '0')).join('');
const hexASalt = h => new Uint8Array(h.match(/.{2}/g).map(x => parseInt(x, 16)));

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* ---------- Almacén de usuarios ---------- */
let auth = null;

function authSave() { try { localStorage.setItem(AUTH_KEY, JSON.stringify(auth)); } catch (e) { /* cuota */ } }

async function authLoad() {
  try {
    const raw = localStorage.getItem(AUTH_KEY);
    if (raw) {
      auth = JSON.parse(raw);
      if (auth && Array.isArray(auth.usuarios) && auth.usuarios.length) return;
    }
  } catch (e) { /* regenerar */ }
  // Primera vez: crear cuentas iniciales con hash
  auth = { usuarios: [], intentos: {} };
  for (const def of AUTH_DEFAULT) {
    const salt = nuevoSalt();
    auth.usuarios.push({
      user: def.correo.toLowerCase(),
      correo: def.correo.toLowerCase(),
      nombre: def.nombre,
      role: def.role,
      salt: saltHex(salt),
      hash: await sha256(def.pass + saltHex(salt)),
      creado: new Date().toISOString(),
      ultimoAcceso: null,
      force: true
    });
  }
  authSave();
}

function cuentasPorRol(role) { return auth.usuarios.filter(u => u.role === role).length; }

function estadoIntentos(user) {
  auth.intentos = auth.intentos || {};
  const e = auth.intentos[user];
  if (!e) return { bloqueado: false, restantes: MAX_INTENTOS };
  if (e.hasta && Date.now() < e.hasta) return { bloqueado: true, minutos: Math.ceil((e.hasta - Date.now()) / 60000) };
  return { bloqueado: false, restantes: MAX_INTENTOS - (e.n || 0) };
}

function registrarIntento(user, ok) {
  auth.intentos = auth.intentos || {};
  if (ok) { delete auth.intentos[user]; return; }
  const e = auth.intentos[user] || { n: 0 };
  e.n++;
  if (e.n >= MAX_INTENTOS) { e.hasta = Date.now() + MINUTOS_BLOQUEO * 60000; e.n = 0; }
  auth.intentos[user] = e;
  authSave();
}

/* ---------- Sesión ---------- */
function sesionActual() {
  try { return JSON.parse(sessionStorage.getItem('proGanadoSesion')); } catch (e) { return null; }
}

/* Respaldo: si el servidor no responde (página abierta sin servidor),
   el código se genera y valida localmente para que NUNCA quedes fuera. */
function codigoLocal(correo) {
  const c = String(Math.floor(100000 + Math.random() * 900000));
  sessionStorage.setItem('proGanadoCodigoLocal', JSON.stringify({ correo: String(correo).toLowerCase(), codigo: c, exp: Date.now() + 5 * 60000, intentos: 0 }));
  return c;
}
function verificarCodigoLocal(correo, codigo) {
  try {
    const r = JSON.parse(sessionStorage.getItem('proGanadoCodigoLocal'));
    if (!r || r.correo !== String(correo).toLowerCase()) return { ok: false, msg: 'No hay código activo. Solicita uno nuevo.' };
    if (Date.now() > r.exp) { sessionStorage.removeItem('proGanadoCodigoLocal'); return { ok: false, msg: 'El código expiró. Solicita uno nuevo.' }; }
    if (r.intentos >= 3) { sessionStorage.removeItem('proGanadoCodigoLocal'); return { ok: false, msg: 'Demasiados intentos. Solicita un código nuevo.' }; }
    if (cleanStr(codigo) !== r.codigo) { r.intentos++; sessionStorage.setItem('proGanadoCodigoLocal', JSON.stringify(r)); return { ok: false, msg: 'Código incorrecto.' }; }
    sessionStorage.removeItem('proGanadoCodigoLocal');
    return { ok: true };
  } catch (e) { return { ok: false, msg: 'No hay código activo. Solicita uno nuevo.' }; }
}

/* Paso 1: validar credenciales y pedir el código al servidor */
async function iniciarPaso1(user, pass) {
  const norm = cleanStr(user).toLowerCase();
  const estado = estadoIntentos(norm);
  if (estado.bloqueado) return { ok: false, msg: 'Demasiados intentos. Espera ' + estado.minutos + ' min.' };
  const u = auth.usuarios.find(x => x.user.toLowerCase() === norm);
  const hash = u ? await sha256(cleanStr(pass) + u.salt) : '';
  if (!u || hash !== u.hash) {
    registrarIntento(norm, false);
    const nuevo = estadoIntentos(norm);
    return { ok: false, msg: nuevo.bloqueado ? 'Cuenta bloqueada ' + MINUTOS_BLOQUEO + ' minutos por intentos fallidos.' : 'Correo o contraseña incorrectos. Intentos restantes: ' + nuevo.restantes + '.' };
  }
  // Credenciales OK → pedir código al servidor; si no hay, modo local
  let data = null;
  try {
    const r = await fetch('/api/enviar-codigo', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ correo: u.correo || u.user })
    });
    data = await r.json();
    if (!data.ok) return { ok: false, msg: data.msg || 'No se pudo enviar el código.' };
  } catch (e) {
    data = { ok: true, modo_prueba: true, codigo_prueba: codigoLocal(u.correo || u.user), local: true };
  }
  registrarIntento(norm, true);
  return { ok: true, correo: u.correo || u.user, nombre: u.nombre, role: u.role, modoPrueba: !!data.modo_prueba, codigoPrueba: data.codigo_prueba || null, local: !!data.local };
}

/* Paso 2: validar el código de 6 dígitos y abrir la sesión */
async function iniciarPaso2(correo, codigo, recordar) {
  let servidorVivo = true;
  try {
    const r = await fetch('/api/verificar-codigo', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ correo, codigo })
    });
    const data = await r.json();
    if (!data.ok) return { ok: false, msg: data.msg || 'Código incorrecto.' };
  } catch (e) {
    servidorVivo = false; // sin servidor → validar contra el código local
    const v = verificarCodigoLocal(correo, codigo);
    if (!v.ok) return v;
  }
  const u = auth.usuarios.find(x => (x.correo || x.user).toLowerCase() === correo.toLowerCase());
  if (!u) return { ok: false, msg: 'Cuenta no encontrada.' };
  u.ultimoAcceso = new Date().toISOString();
  authSave();
  const sesion = { user: u.user, nombre: u.nombre, role: u.role, ts: Date.now(), expira: Date.now() + DIAS_SESION * 86400000 };
  const store = recordar ? localStorage : sessionStorage;
  store.setItem('proGanadoSesion', JSON.stringify(sesion));
  return { ok: true, sesion };
}

function cleanStr(v) { return String(v == null ? '' : v).trim(); }

function cerrarSesion() {
  sessionStorage.removeItem('proGanadoSesion');
  localStorage.removeItem('proGanadoSesion');
  mostrarLogin();
}

function sesionValida() {
  const s = sesionActual();
  if (!s || !s.expira || Date.now() > s.expira) { cerrarSesion(); return null; }
  return s;
}

/* ---------- Permisos por rol ---------- */
function esAdmin() { return (sesionActual() || {}).role === 'admin'; }

/* ---------- Interfaz de login (2 pasos) ---------- */
let pasoActual = 'credenciales';
let pendiente = null; // { correo, nombre, role }

function mostrarLogin() {
  document.body.classList.add('modo-login');
  const v = $a('#loginView'); if (v) v.style.display = 'flex';
  const app = $a('.app-shell'); if (app) app.style.display = 'none';
  pasoActual = 'credenciales';
  pendiente = null;
  pintarPaso();
  $a('#loginUser').value = '';
  $a('#loginPass').value = '';
  $a('#loginRecordar').checked = false;
  setLoginMsg('');
}

function pintarPaso() {
  const paso1 = $a('#pasoCredenciales'), paso2 = $a('#pasoCodigo');
  if (!paso1 || !paso2) return;
  paso1.style.display = pasoActual === 'credenciales' ? '' : 'none';
  paso2.style.display = pasoActual === 'codigo' ? '' : 'none';
  const sub = $a('.login-form > p');
  if (sub) {
    sub.textContent = pasoActual === 'credenciales'
      ? 'Ingresa tus credenciales para entrar al sistema.'
      : 'Enviamos un código de 6 dígitos a ' + (pendiente ? pendiente.correo : '') + '. Ingresa el código para continuar.';
  }
  if (pasoActual === 'codigo') { $a('#loginCodigo').value = ''; setTimeout(() => $a('#loginCodigo').focus(), 50); }
}

function volverAPaso1() {
  pasoActual = 'credenciales';
  pendiente = null;
  pintarPaso();
  setLoginMsg('');
}

function mostrarApp() {
  document.body.classList.remove('modo-login');
  const v = $a('#loginView'); if (v) v.style.display = 'none';
  const app = $a('.app-shell'); if (app) app.style.display = '';
  aplicarPermisosRol();
}

function setLoginMsg(msg, tipo) {
  const el = $a('#loginMsg');
  if (!el) return;
  el.textContent = msg || '';
  el.className = 'login-msg' + (tipo === 'ok' ? ' ok' : '');
}

/* ---------- Aplicar permisos visibles según rol ---------- */
function aplicarPermisosRol() {
  const s = sesionActual() || {};
  const admin = s.role === 'admin';
  // Iniciales del usuario en el perfil
  const iniciales = cleanStr(s.nombre).split(/\s+/).map(p => p[0]).join('').slice(0, 2).toUpperCase() || 'US';
  const chip = $a('#perfilChip');
  if (chip) {
    chip.textContent = iniciales;
    chip.title = s.nombre + ' · ' + (admin ? 'Administrador' : 'Usuario');
    chip.classList.toggle('es-admin', admin);
  }
  // Chip de sesión en el encabezado
  const chipNombre = $a('#chipNombre'), chipRol = $a('#chipRol'), chipS = $a('#sessionChip');
  if (chipNombre) chipNombre.textContent = s.nombre || '—';
  if (chipRol) chipRol.textContent = admin ? 'Administrador' : 'Usuario';
  if (chipS) chipS.classList.toggle('admin', admin);
  // Menú Usuarios solo para admin
  const navU = $a('#navUsuarios');
  if (navU) navU.style.display = admin ? 'flex' : 'none';
}

/* ---------- Página de administración de usuarios ---------- */
function renderUsuarios() {
  const cont = $a('#usuariosTabla'); if (!cont) return;
  cont.replaceChildren();
  for (const u of auth.usuarios) {
    const tr = document.createElement('tr');
    const tdUser = document.createElement('td');
    tdUser.innerHTML = '<strong>' + escapeHtml(u.nombre) + '</strong><small>' + escapeHtml(u.user) + '</small>';
    tr.append(tdUser);
    const tdRol = document.createElement('td');
    const spanRol = document.createElement('span');
    spanRol.className = 'badge ' + (u.role === 'admin' ? 'b-amber' : 'b-green');
    spanRol.textContent = u.role === 'admin' ? 'Administrador' : 'Usuario';
    tdRol.append(spanRol);
    tr.append(tdRol);
    const tdUlt = document.createElement('td');
    tdUlt.textContent = u.ultimoAcceso ? new Date(u.ultimoAcceso).toLocaleString('es-CO', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : 'Nunca';
    tr.append(tdUlt);
    const tdAcc = document.createElement('td');
    const s = sesionActual() || {};
    if (u.user !== s.user) {
      const btnDel = document.createElement('button');
      btnDel.className = 'mini-btn danger';
      btnDel.textContent = '🗑';
      btnDel.title = 'Eliminar cuenta';
      btnDel.addEventListener('click', () => eliminarUsuario(u.user));
      tdAcc.append(btnDel);
    } else {
      const span = document.createElement('span');
      span.className = 'tag';
      span.textContent = 'Sesión actual';
      tdAcc.append(span);
    }
    tr.append(tdAcc);
    cont.append(tr);
  }
  $a('#countAdmins').textContent = cuentasPorRol('admin') + ' / ' + MAX_ADMINS;
  $a('#countUsers').textContent = cuentasPorRol('usuario') + ' / ' + MAX_USUARIOS;
  const totalEl = $a('#countTotal');
  if (totalEl) totalEl.textContent = auth.usuarios.length;
}

function eliminarUsuario(user) {
  const u = auth.usuarios.find(x => x.user === user);
  if (!u) return;
  const n = confirm('¿Eliminar la cuenta "' + u.nombre + '" (' + u.user + ')? Esta acción no se puede deshacer.');
  if (!n) return;
  auth.usuarios = auth.usuarios.filter(x => x.user !== user);
  authSave();
  renderUsuarios();
}

async function crearCuenta(ev) {
  ev.preventDefault();
  const f = ev.target;
  const correo = cleanStr(f.newUser.value).toLowerCase();
  const nombre = cleanStr(f.newName.value);
  const pass = String(f.newPass.value);
  const role = f.newRole.value;
  const msgEl = $a('#newUserMsg');
  msgEl.textContent = '';
  msgEl.className = 'form-msg';

  if (!ES_CORREO(correo)) { msgEl.textContent = 'El usuario debe ser un correo válido (ej. nombre@gmail.com) — allí llegará el código de seguridad.'; return; }
  if (pass.length < 8) { msgEl.textContent = 'La contraseña debe tener al menos 8 caracteres.'; return; }
  if (!/[A-Za-z]/.test(pass) || !/\d/.test(pass)) { msgEl.textContent = 'La contraseña debe combinar letras y números.'; return; }
  if (auth.usuarios.some(u => u.user.toLowerCase() === correo.toLowerCase())) { msgEl.textContent = 'Ese correo ya está registrado.'; return; }
  if (role === 'admin' && cuentasPorRol('admin') >= MAX_ADMINS) { msgEl.textContent = 'Límite alcanzado: máximo ' + MAX_ADMINS + ' administradores.'; return; }
  if (role === 'usuario' && cuentasPorRol('usuario') >= MAX_USUARIOS) { msgEl.textContent = 'Límite alcanzado: máximo ' + MAX_USUARIOS + ' usuarios.'; return; }

  const salt = nuevoSalt();
  const hash = await sha256(pass + saltHex(salt));
  auth.usuarios.push({
    user: correo, correo, nombre, role,
    salt: saltHex(salt),
    hash: hash,
    creado: new Date().toISOString(),
    ultimoAcceso: null
  });
  authSave();
  f.reset();
  msgEl.textContent = '✓ Cuenta creada para ' + nombre + '. El código de ingreso llegará a ' + correo + '.';
  msgEl.className = 'form-msg ok';
  renderUsuarios();
}

/* ---------- Wire-up ---------- */
function initAuth() {
  $a('#formLogin').addEventListener('submit', async ev => {
    ev.preventDefault();
    const btn = $a('#btnLogin');
    if (pasoActual === 'credenciales') {
      const userIn = $a('#loginUser').value;
      if (!ES_CORREO(userIn)) { setLoginMsg('Escribe tu correo Gmail completo (ej. nombre@gmail.com).'); return; }
      if (!cleanStr($a('#loginPass').value)) { setLoginMsg('Escribe tu contraseña.'); return; }
      btn.disabled = true; btn.textContent = 'Verificando…';
      let r;
      try { r = await iniciarPaso1(userIn, $a('#loginPass').value); }
      catch (e) { btn.disabled = false; btn.textContent = 'Entrar'; setLoginMsg('Error inesperado: ' + e.message); return; }
      btn.disabled = false; btn.textContent = 'Entrar';
      if (!r.ok) { setLoginMsg(r.msg); return; }
      pendiente = { correo: r.correo, nombre: r.nombre, role: r.role };
      pasoActual = 'codigo';
      pintarPaso();
      if (r.modoPrueba && r.codigoPrueba) {
        const aviso = $a('#modoPruebaAviso');
        if (aviso) { aviso.style.display = ''; aviso.querySelector('b').textContent = r.codigoPrueba; }
      }
      setLoginMsg('');
    } else {
      const codigo = cleanStr($a('#loginCodigo').value);
      if (!/^\d{6}$/.test(codigo)) { setLoginMsg('El código tiene 6 dígitos.'); return; }
      btn.disabled = true; btn.textContent = 'Validando…';
      let r;
      try { r = await iniciarPaso2(pendiente.correo, codigo, $a('#loginRecordar').checked); }
      catch (e) { btn.disabled = false; btn.textContent = 'Entrar'; setLoginMsg('Error inesperado: ' + e.message); return; }
      btn.disabled = false; btn.textContent = 'Entrar';
      if (!r.ok) { setLoginMsg(r.msg); return; }
      setLoginMsg('');
      mostrarApp();
      renderAll();
    }
  });
  const btnVolver = $a('#btnVolverPaso1');
  if (btnVolver) btnVolver.addEventListener('click', volverAPaso1);
  const btnReenviar = $a('#btnReenviar');
  if (btnReenviar) btnReenviar.addEventListener('click', async () => {
    if (!pendiente) return;
    btnReenviar.disabled = true;
    try {
      const r = await fetch('/api/enviar-codigo', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ correo: pendiente.correo })
      });
      const data = await r.json();
      if (data.ok && data.modo_prueba) { const av = $a('#modoPruebaAviso'); if (av) { av.style.display = ''; av.querySelector('b').textContent = data.codigo_prueba; } }
      setLoginMsg(data.ok ? 'Código reenviado.' : (data.msg || 'No se pudo reenviar.'), data.ok ? 'ok' : '');
    } catch (e) {
      const c = codigoLocal(pendiente.correo);
      const av = $a('#modoPruebaAviso');
      if (av) { av.style.display = ''; av.querySelector('b').textContent = c; }
      setLoginMsg('Código generado localmente (servidor no disponible).', 'ok');
    }
    btnReenviar.disabled = false;
  });
  $a('#btnLogout').addEventListener('click', cerrarSesion);
  $a('#formNewUser').addEventListener('submit', crearCuenta);
  const navU = $a('#navUsuarios');
  if (navU) navU.addEventListener('click', () => setTimeout(renderUsuarios, 0));
}

/* ---------- Arranque de autenticación ----------
   Solo decide visibilidad; el renderizado lo hace app.js al cargar
   (renderAll vive allí y llenar el DOM oculto no tiene costo visible). */
(async function authBoot() {
  await authLoad();
  initAuth();
  if (sesionValida()) mostrarApp();
  else mostrarLogin();
  window.authBootDone = true;
})();