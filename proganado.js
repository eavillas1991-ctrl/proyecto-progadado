/* ============================================================
   ProGanado — Autenticación local (2FA por correo) y usuarios
   - Máximo 4 administradores y 7 usuarios (total 11 cuentas)
   - Contraseñas con PBKDF2-SHA256 + salt único por usuario
   - Bloqueo temporal tras 5 intentos fallidos (5 minutos)
   - Roles: admin (todo) / usuario (consulta y registros)
   - Sesión de 7 días (sessionStorage o localStorage si "recordar")
   ============================================================ */
'use strict';

const AUTH_KEY = 'proGanadoAuth_v2';
const $a = sel => document.querySelector(sel);
const MAX_ADMINS = 4;
const MAX_USUARIOS = 7;
const MAX_INTENTOS = 5;
const MINUTOS_BLOQUEO = 5;
const DIAS_SESION = 7;
const PBKDF2_ITER = 150000;

/* No se incluyen cuentas ni contraseñas por defecto. En el primer arranque
   el responsable crea la cuenta administradora desde la pantalla de acceso;
   el correo de esa cuenta recibe los códigos 2FA. */

const ES_CORREO = v => /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/.test(String(v || '').trim().toLowerCase());
const cleanStr = v => String(v == null ? '' : v).trim();
const bytesAHex = a => [...a].map(b => b.toString(16).padStart(2, '0')).join('');
const hexABytes = h => new Uint8Array((String(h || '').match(/.{2}/g) || []).map(x => parseInt(x, 16)));

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function nuevoSaltHex() {
  const a = new Uint8Array(16);
  if (window.crypto && window.crypto.getRandomValues) crypto.getRandomValues(a);
  else for (let i = 0; i < a.length; i++) a[i] = Math.floor(Math.random() * 256);
  return bytesAHex(a);
}

// SHA-256 compatible con las versiones anteriores (migración de hashes).
async function sha256(texto) {
  if (window.crypto && window.crypto.subtle) {
    try {
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(texto));
      return bytesAHex(new Uint8Array(buf));
    } catch (e) {}
  }
  let hash = 0;
  for (let i = 0; i < texto.length; i++) {
    hash = (hash << 5) - hash + texto.charCodeAt(i);
    hash |= 0;
  }
  return 'local_' + Math.abs(hash).toString(16);
}

async function hashPassword(pass, salt) {
  if (window.crypto && window.crypto.subtle) {
    try {
      const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveBits']);
      const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: hexABytes(salt), iterations: PBKDF2_ITER, hash: 'SHA-256' },
        key, 256
      );
      return { algo: 'pbkdf2', hash: bytesAHex(new Uint8Array(bits)), iter: PBKDF2_ITER };
    } catch (e) { /* respaldo local */ }
  }
  return { algo: 'sha256', hash: await sha256(pass + salt), iter: 0 };
}

async function verificarPassword(u, pass) {
  if (!u || !u.hash) return false;
  if (u.algo === 'pbkdf2') {
    if (!(window.crypto && window.crypto.subtle)) return false;
    try {
      const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveBits']);
      const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: hexABytes(u.salt || ''), iterations: Number(u.iter) || PBKDF2_ITER, hash: 'SHA-256' },
        key, 256
      );
      return bytesAHex(new Uint8Array(bits)) === u.hash;
    } catch (e) { return false; }
  }
  // Compatibilidad: SHA-256 sin salt (versiones anteriores) o con salt.
  return (await sha256(pass + (u.salt || ''))) === u.hash;
}

async function actualizarHash(u, pass) {
  if (!u || u.algo === 'pbkdf2') return;
  const salt = nuevoSaltHex();
  const r = await hashPassword(pass, salt);
  u.salt = salt; u.hash = r.hash; u.algo = r.algo; u.iter = r.iter;
  authSave();
}

/* ---------- Almacén de usuarios ---------- */
let auth = null;

function authSave() {
  try { localStorage.setItem(AUTH_KEY, JSON.stringify(auth)); } catch (e) { /* cuota llena */ }
}

async function authLoad() {
  try {
    const raw = localStorage.getItem(AUTH_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && Array.isArray(parsed.usuarios)) {
        auth = parsed;
        auth.intentos = auth.intentos || {};
        for (const u of auth.usuarios) {
          u.user = String(u.user || u.correo || '').toLowerCase();
          u.correo = String(u.correo || u.user).toLowerCase();
        }
        authSave();
        return;
      }
    }
  } catch (e) { /* datos corruptos: regenerar */ }

  // Primer uso: sin cuentas. El administrador se crea desde la pantalla de acceso.
  auth = { usuarios: [], intentos: {} };
  authSave();
}

function cuentasPorRol(role) {
  return (auth && auth.usuarios ? auth.usuarios : []).filter(u => u.role === role).length;
}

function estadoIntentos(user) {
  if (!auth) return { bloqueado: false, restantes: MAX_INTENTOS };
  auth.intentos = auth.intentos || {};
  const e = auth.intentos[user];
  if (!e) return { bloqueado: false, restantes: MAX_INTENTOS };
  if (e.hasta && Date.now() < e.hasta) return { bloqueado: true, minutos: Math.ceil((e.hasta - Date.now()) / 60000) };
  return { bloqueado: false, restantes: MAX_INTENTOS - (e.n || 0) };
}

function registrarIntento(user, ok) {
  if (!auth) return;
  auth.intentos = auth.intentos || {};
  if (ok) { delete auth.intentos[user]; authSave(); return; }
  const e = auth.intentos[user] || { n: 0 };
  e.n++;
  if (e.n >= MAX_INTENTOS) { e.hasta = Date.now() + MINUTOS_BLOQUEO * 60000; e.n = 0; }
  auth.intentos[user] = e;
  authSave();
}

/* ---------- Sesión ---------- */
function sesionActual() {
  try {
    const raw = sessionStorage.getItem('proGanadoSesion') || localStorage.getItem('proGanadoSesion');
    const s = raw ? JSON.parse(raw) : null;
    if (!s || !auth || !auth.usuarios.some(u => u.user === s.user)) return null;
    return s;
  } catch (e) { return null; }
}

function sesionValida() {
  const s = sesionActual();
  if (!s || !s.expira || Date.now() > s.expira) { cerrarSesion(); return null; }
  return s;
}

function guardarSesion(sesion, recordar) {
  try {
    sessionStorage.removeItem('proGanadoSesion');
    localStorage.removeItem('proGanadoSesion');
    const store = recordar ? localStorage : sessionStorage;
    store.setItem('proGanadoSesion', JSON.stringify(sesion));
  } catch (e) { /* almacenamiento no disponible */ }
}

function cerrarSesion() {
  try {
    sessionStorage.removeItem('proGanadoSesion');
    localStorage.removeItem('proGanadoSesion');
    sessionStorage.removeItem('proGanadoCodigoLocal');
  } catch (e) {}
  mostrarLogin();
}

/* ---------- Permisos por rol ---------- */
function esAdmin() { return (sesionActual() || {}).role === 'admin'; }

function aplicarPermisosRol() {
  const s = sesionActual() || {};
  const admin = s.role === 'admin';
  const nombre = cleanStr(s.nombre || s.user || '');
  const iniciales = nombre.split(/\s+/).map(p => p[0]).join('').slice(0, 2).toUpperCase() || 'US';
  const chip = $a('#perfilChip');
  if (chip) {
    chip.textContent = iniciales;
    chip.title = (s.nombre || s.user || '') + ' · ' + (admin ? 'Administrador' : 'Usuario');
    chip.classList.toggle('es-admin', admin);
  }
  const chipNombre = $a('#chipNombre'), chipRol = $a('#chipRol'), chipS = $a('#sessionChip');
  if (chipNombre) chipNombre.textContent = s.nombre || '—';
  if (chipRol) chipRol.textContent = admin ? 'Administrador' : 'Usuario';
  if (chipS) chipS.classList.toggle('admin', admin);
  const navU = $a('#navUsuarios');
  if (navU) navU.style.display = admin ? 'flex' : 'none';
  if (!admin && document.querySelector('#usuarios.active-page')) {
    const inicio = document.querySelector('[data-page="inicio"]');
    if (inicio) inicio.click();
  }
}

/* ---------- Interfaz de login (2 pasos) ---------- */
let pasoActual = 'credenciales';
let pendiente = null;

function setLoginMsg(msg, tipo) {
  const el = $a('#loginMsg');
  if (!el) return;
  el.textContent = msg || '';
  el.className = 'login-msg' + (tipo === 'ok' ? ' ok' : '');
}

function pintarPaso() {
  const paso1 = $a('#pasoCredenciales'), paso2 = $a('#pasoCodigo'), pasoCfg = $a('#pasoConfig');
  if (!paso1 || !paso2 || !pasoCfg) return;
  paso1.style.display = pasoActual === 'credenciales' ? '' : 'none';
  paso2.style.display = pasoActual === 'codigo' ? '' : 'none';
  pasoCfg.style.display = pasoActual === 'config' ? '' : 'none';
  const sub = $a('.login-form > p');
  if (sub) {
    sub.textContent = pasoActual === 'config'
      ? 'Primer uso: crea la cuenta administradora de la finca.'
      : pasoActual === 'credenciales'
        ? 'Ingresa tus credenciales para entrar al sistema.'
        : 'Enviamos un código de 6 dígitos a ' + (pendiente ? pendiente.correo : '') + '. Ingresa el código para continuar.';
  }
  const btn = $a('#btnLogin');
  if (btn) btn.textContent = pasoActual === 'config' ? 'Crear cuenta de administrador' : 'Entrar';
  if (pasoActual === 'codigo') {
    const input = $a('#loginCodigo');
    if (input) { input.value = ''; setTimeout(() => input.focus(), 50); }
  } else {
    const aviso = $a('#modoPruebaAviso');
    if (aviso) aviso.style.display = 'none';
  }
}

function volverAPaso1() {
  pasoActual = auth && auth.usuarios.length === 0 ? 'config' : 'credenciales';
  pendiente = null;
  pintarPaso();
  setLoginMsg('');
}

function mostrarApp() {
  document.body.classList.remove('modo-login');
  const v = $a('#loginView'); if (v) v.style.display = 'none';
  const app = $a('.app-shell'); if (app) app.style.display = '';
  aplicarPermisosRol();
  if (typeof renderAll === 'function') renderAll();
  renderUsuarios();
}

function mostrarLogin() {
  document.body.classList.add('modo-login');
  const v = $a('#loginView'); if (v) v.style.display = 'flex';
  const app = $a('.app-shell'); if (app) app.style.display = 'none';
  pasoActual = auth && auth.usuarios.length === 0 ? 'config' : 'credenciales';
  pendiente = null;
  pintarPaso();
  const user = $a('#loginUser'); if (user) user.value = '';
  const pass = $a('#loginPass'); if (pass) pass.value = '';
  const rec = $a('#loginRecordar'); if (rec) rec.checked = false;
  const cfgForm = $a('#formLogin');
  if (cfgForm) ['setupName', 'setupUser', 'setupPass', 'setupPass2'].forEach(n => { if (cfgForm.elements[n]) cfgForm.elements[n].value = ''; });
  setLoginMsg('');
}

/* ---------- Código 2FA local (si el servidor no responde) ---------- */
function codigoLocal(correo) {
  const azar = new Uint32Array(1);
  if (window.crypto && window.crypto.getRandomValues) crypto.getRandomValues(azar);
  else azar[0] = Math.floor(Math.random() * 0xFFFFFFFF);
  const c = String(100000 + (azar[0] % 900000));
  sessionStorage.setItem('proGanadoCodigoLocal', JSON.stringify({ correo: String(correo).toLowerCase(), codigo: c, exp: Date.now() + 5 * 60000, intentos: 0 }));
  return c;
}

function verificarCodigoLocal(correo, codigo) {
  try {
    const r = JSON.parse(sessionStorage.getItem('proGanadoCodigoLocal'));
    if (!r || r.correo !== String(correo).toLowerCase()) return { ok: false, msg: 'No hay código activo. Solicita uno nuevo.' };
    if (Date.now() > r.exp) { sessionStorage.removeItem('proGanadoCodigoLocal'); return { ok: false, msg: 'El código expiró. Solicita uno nuevo.' }; }
    if (r.intentos >= 3) { sessionStorage.removeItem('proGanadoCodigoLocal'); return { ok: false, msg: 'Demasiados intentos. Solicita un código nuevo.' }; }
    if (cleanStr(codigo) !== r.codigo) {
      r.intentos++;
      sessionStorage.setItem('proGanadoCodigoLocal', JSON.stringify(r));
      return { ok: false, msg: 'Código incorrecto.' };
    }
    sessionStorage.removeItem('proGanadoCodigoLocal');
    return { ok: true };
  } catch (e) { return { ok: false, msg: 'No hay código activo. Solicita uno nuevo.' }; }
}

async function iniciarPaso1(user, pass) {
  const norm = cleanStr(user).toLowerCase();
  const estado = estadoIntentos(norm);
  if (estado.bloqueado) return { ok: false, msg: 'Demasiados intentos. Espera ' + estado.minutos + ' min.' };

  const u = auth.usuarios.find(x => x.user.toLowerCase() === norm);
  const ok = u ? await verificarPassword(u, cleanStr(pass)) : false;
  if (!u || !ok) {
    registrarIntento(norm, false);
    const nuevo = estadoIntentos(norm);
    return {
      ok: false,
      msg: nuevo.bloqueado
        ? 'Cuenta bloqueada ' + MINUTOS_BLOQUEO + ' minutos por intentos fallidos.'
        : 'Correo o contraseña incorrectos. Intentos restantes: ' + nuevo.restantes + '.'
    };
  }

  await actualizarHash(u, cleanStr(pass));

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
  return {
    ok: true,
    correo: u.correo || u.user,
    nombre: u.nombre,
    role: u.role,
    modoPrueba: !!data.modo_prueba,
    codigoPrueba: data.codigo_prueba || null,
    local: !!data.local
  };
}

async function iniciarPaso2(correo, codigo, recordar) {
  try {
    const r = await fetch('/api/verificar-codigo', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ correo, codigo })
    });
    const data = await r.json();
    if (!data.ok) return { ok: false, msg: data.msg || 'Código incorrecto.' };
  } catch (e) {
    // Sin servidor (file://) se valida el código local generado en el paso 1.
    const v = verificarCodigoLocal(correo, codigo);
    if (!v.ok) return v;
  }

  const u = auth.usuarios.find(x => (x.correo || x.user).toLowerCase() === String(correo).toLowerCase());
  if (!u) return { ok: false, msg: 'Cuenta no encontrada.' };
  u.ultimoAcceso = new Date().toISOString();
  authSave();
  const sesion = { user: u.user, nombre: u.nombre, role: u.role, ts: Date.now(), expira: Date.now() + DIAS_SESION * 86400000 };
  guardarSesion(sesion, recordar);
  return { ok: true, sesion };
}

/* ---------- Administración de usuarios ---------- */
function renderUsuarios() {
  const cont = $a('#usuariosTabla');
  if (!cont || !auth) return;
  cont.replaceChildren();
  const s = sesionActual() || {};
  for (const u of auth.usuarios) {
    const tr = document.createElement('tr');
    const tdUser = document.createElement('td');
    tdUser.innerHTML = '<strong>' + escapeHtml(u.nombre || 'Sin nombre') + '</strong><small>' + escapeHtml(u.user) + '</small>';
    tr.append(tdUser);

    const tdRol = document.createElement('td');
    const spanRol = document.createElement('span');
    spanRol.className = 'badge ' + (u.role === 'admin' ? 'b-amber' : 'b-green');
    spanRol.textContent = u.role === 'admin' ? 'Administrador' : 'Usuario';
    tdRol.append(spanRol);
    tr.append(tdRol);

    const tdUlt = document.createElement('td');
    tdUlt.textContent = u.ultimoAcceso
      ? new Date(u.ultimoAcceso).toLocaleString('es-CO', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
      : 'Nunca';
    tr.append(tdUlt);

    const tdAcc = document.createElement('td');
    tdAcc.style.whiteSpace = 'nowrap';
    const ultimoAdmin = u.role === 'admin' && cuentasPorRol('admin') <= 1;
    const btnPass = document.createElement('button');
    btnPass.className = 'mini-btn';
    btnPass.textContent = 'Clave';
    btnPass.title = 'Cambiar contraseña';
    btnPass.addEventListener('click', () => abrirCambioPassword(u.user));
    if (u.user === s.user) {
      const span = document.createElement('span');
      span.className = 'tag';
      span.textContent = 'Sesión actual';
      tdAcc.append(span, ' ', btnPass);
    } else if (ultimoAdmin) {
      const span = document.createElement('span');
      span.className = 'tag';
      span.textContent = 'Único administrador';
      tdAcc.append(span, ' ', btnPass);
    } else {
      const btnDel = document.createElement('button');
      btnDel.className = 'mini-btn danger';
      btnDel.textContent = '🗑';
      btnDel.title = 'Eliminar cuenta';
      btnDel.addEventListener('click', () => eliminarUsuario(u.user));
      tdAcc.append(btnPass, btnDel);
    }
    tr.append(tdAcc);
    cont.append(tr);
  }
  const countAdmins = $a('#countAdmins'), countUsers = $a('#countUsers'), countTotal = $a('#countTotal');
  if (countAdmins) countAdmins.textContent = cuentasPorRol('admin') + ' / ' + MAX_ADMINS;
  if (countUsers) countUsers.textContent = cuentasPorRol('usuario') + ' / ' + MAX_USUARIOS;
  if (countTotal) countTotal.textContent = auth.usuarios.length;
}

let passTarget = null;
function abrirCambioPassword(user) {
  if (!auth) return;
  const u = auth.usuarios.find(x => x.user === user);
  const form = $a('#formPassword');
  if (!u || !form) return;
  passTarget = user;
  form.reset();
  $a('#passTarget').textContent = 'Cuenta: ' + (u.nombre || u.user) + ' · ' + u.user;
  const msg = $a('#passMsg');
  if (msg) { msg.textContent = ''; msg.className = 'form-msg'; }
  document.getElementById('modalPassword').showModal();
  setTimeout(() => form.elements.pass1.focus(), 50);
}

async function guardarPassword(ev) {
  ev.preventDefault();
  if (!auth || !passTarget) return;
  const f = ev.target;
  const p1 = String(f.pass1.value), p2 = String(f.pass2.value);
  const msg = $a('#passMsg');
  if (!msg) return;
  msg.textContent = ''; msg.className = 'form-msg';
  if (p1.length < 8) { msg.textContent = 'La contraseña debe tener al menos 8 caracteres.'; return; }
  if (!/[A-Za-z]/.test(p1) || !/\d/.test(p1)) { msg.textContent = 'La contraseña debe combinar letras y números.'; return; }
  if (p1 !== p2) { msg.textContent = 'Las contraseñas no coinciden.'; return; }
  const u = auth.usuarios.find(x => x.user === passTarget);
  if (!u) { msg.textContent = 'La cuenta ya no existe.'; return; }
  const salt = nuevoSaltHex();
  const r = await hashPassword(p1, salt);
  u.salt = salt; u.hash = r.hash; u.algo = r.algo; u.iter = r.iter;
  authSave();
  msg.textContent = '✓ Contraseña actualizada.';
  msg.className = 'form-msg ok';
  setTimeout(() => {
    const d = document.getElementById('modalPassword');
    if (d && d.open) d.close();
    renderUsuarios();
  }, 700);
}

function eliminarUsuario(user) {
  if (!auth) return;
  const u = auth.usuarios.find(x => x.user === user);
  if (!u) return;
  const s = sesionActual() || {};
  if (u.user === s.user) { alert('No puedes eliminar la cuenta con la que estás conectado.'); return; }
  if (u.role === 'admin' && cuentasPorRol('admin') <= 1) { alert('Debe existir al menos un administrador.'); return; }
  if (!confirm('¿Eliminar la cuenta "' + (u.nombre || u.user) + '" (' + u.user + ')? Esta acción no se puede deshacer.')) return;
  auth.usuarios = auth.usuarios.filter(x => x.user !== user);
  authSave();
  renderUsuarios();
}

async function crearCuenta(ev) {
  ev.preventDefault();
  if (!auth) return;
  const f = ev.target;
  const correo = cleanStr(f.newUser.value).toLowerCase();
  const nombre = cleanStr(f.newName.value);
  const pass = String(f.newPass.value);
  const role = f.newRole.value;
  const msgEl = $a('#newUserMsg');
  if (!msgEl) return;
  msgEl.textContent = '';
  msgEl.className = 'form-msg';

  if (!ES_CORREO(correo)) { msgEl.textContent = 'El usuario debe ser un correo válido (ej. nombre@gmail.com); allí llegará el código de seguridad.'; return; }
  if (pass.length < 8) { msgEl.textContent = 'La contraseña debe tener al menos 8 caracteres.'; return; }
  if (!/[A-Za-z]/.test(pass) || !/\d/.test(pass)) { msgEl.textContent = 'La contraseña debe combinar letras y números.'; return; }
  if (auth.usuarios.some(u => u.user.toLowerCase() === correo)) { msgEl.textContent = 'Ese correo ya está registrado.'; return; }
  if (role === 'admin' && cuentasPorRol('admin') >= MAX_ADMINS) { msgEl.textContent = 'Límite alcanzado: máximo ' + MAX_ADMINS + ' administradores.'; return; }
  if (role === 'usuario' && cuentasPorRol('usuario') >= MAX_USUARIOS) { msgEl.textContent = 'Límite alcanzado: máximo ' + MAX_USUARIOS + ' usuarios.'; return; }

  const salt = nuevoSaltHex();
  const r = await hashPassword(pass, salt);
  auth.usuarios.push({
    user: correo, correo, nombre, role,
    salt, hash: r.hash, algo: r.algo, iter: r.iter,
    creado: new Date().toISOString(),
    ultimoAcceso: null
  });
  authSave();
  f.reset();
  msgEl.textContent = '✓ Cuenta creada para ' + nombre + '. El código de ingreso llegará a ' + correo + '.';
  msgEl.className = 'form-msg ok';
  renderUsuarios();
}

/* Crea la primera cuenta administradora. Devuelve los datos para iniciar
   sesión o null si la validación falla (el mensaje ya quedó visible). */
async function crearCuentaInicial() {
  const nombre = cleanStr($a('#setupName').value);
  const correo = cleanStr($a('#setupUser').value).toLowerCase();
  const p1 = String($a('#setupPass').value);
  const p2 = String($a('#setupPass2').value);

  if (!nombre) { setLoginMsg('Escribe el nombre del administrador.'); return null; }
  if (!ES_CORREO(correo)) { setLoginMsg('Escribe un correo válido (ej. nombre@gmail.com); allí llegarán los códigos de seguridad.'); return null; }
  if (p1.length < 8) { setLoginMsg('La contraseña debe tener al menos 8 caracteres.'); return null; }
  if (!/[A-Za-z]/.test(p1) || !/\d/.test(p1)) { setLoginMsg('La contraseña debe combinar letras y números.'); return null; }
  if (p1 !== p2) { setLoginMsg('Las contraseñas no coinciden.'); return null; }
  if (!auth || auth.usuarios.length) { setLoginMsg('Ya existe una cuenta registrada. Inicia sesión.'); pasoActual = 'credenciales'; pintarPaso(); return null; }

  const salt = nuevoSaltHex();
  const r = await hashPassword(p1, salt);
  auth.usuarios.push({
    user: correo, correo, nombre, role: 'admin',
    salt, hash: r.hash, algo: r.algo, iter: r.iter,
    creado: new Date().toISOString(),
    ultimoAcceso: null
  });
  authSave();
  ['setupName', 'setupUser', 'setupPass', 'setupPass2'].forEach(n => { const el = $a('#formLogin').elements[n]; if (el) el.value = ''; });
  return { correo, nombre, pass: p1 };
}

/* ---------- Wire-up ---------- */
function initAuth() {
  const formLogin = $a('#formLogin');
  if (!formLogin) return;

  formLogin.addEventListener('submit', async ev => {
    ev.preventDefault();
    const btn = $a('#btnLogin');
    if (pasoActual === 'config') {
      btn.disabled = true; btn.textContent = 'Creando cuenta…';
      let r;
      try {
        const nueva = await crearCuentaInicial();
        if (!nueva) { btn.disabled = false; pintarPaso(); return; }
        r = await iniciarPaso1(nueva.correo, nueva.pass);
      } catch (e) {
        btn.disabled = false; pintarPaso();
        setLoginMsg('Error inesperado: ' + e.message);
        return;
      }
      btn.disabled = false;
      if (!r.ok) { pintarPaso(); setLoginMsg(r.msg); return; }
      pendiente = { correo: r.correo, nombre: r.nombre, role: r.role };
      pasoActual = 'codigo';
      pintarPaso();
      if (r.modoPrueba && r.codigoPrueba) {
        const aviso = $a('#modoPruebaAviso');
        if (aviso) { aviso.style.display = ''; const b = aviso.querySelector('b'); if (b) b.textContent = r.codigoPrueba; }
      }
      setLoginMsg('Cuenta creada. Ingresa el código enviado a tu correo.', 'ok');
    } else if (pasoActual === 'credenciales') {
      const userIn = $a('#loginUser').value;
      const passIn = $a('#loginPass').value;
      if (!ES_CORREO(userIn)) { setLoginMsg('Escribe tu correo completo (ej. nombre@gmail.com).'); return; }
      if (!cleanStr(passIn)) { setLoginMsg('Escribe tu contraseña.'); return; }

      btn.disabled = true; btn.textContent = 'Verificando…';
      let r;
      try { r = await iniciarPaso1(userIn, passIn); }
      catch (e) { btn.disabled = false; btn.textContent = 'Entrar'; setLoginMsg('Error inesperado: ' + e.message); return; }
      btn.disabled = false; btn.textContent = 'Entrar';
      if (!r.ok) { setLoginMsg(r.msg); return; }

      pendiente = { correo: r.correo, nombre: r.nombre, role: r.role };
      pasoActual = 'codigo';
      pintarPaso();
      if (r.modoPrueba && r.codigoPrueba) {
        const aviso = $a('#modoPruebaAviso');
        if (aviso) { aviso.style.display = ''; const b = aviso.querySelector('b'); if (b) b.textContent = r.codigoPrueba; }
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
      if (data.ok && data.modo_prueba) {
        const av = $a('#modoPruebaAviso');
        if (av) { av.style.display = ''; const b = av.querySelector('b'); if (b) b.textContent = data.codigo_prueba; }
      }
      setLoginMsg(data.ok ? 'Código reenviado.' : (data.msg || 'No se pudo reenviar.'), data.ok ? 'ok' : '');
    } catch (e) {
      const c = codigoLocal(pendiente.correo);
      const av = $a('#modoPruebaAviso');
      if (av) { av.style.display = ''; const b = av.querySelector('b'); if (b) b.textContent = c; }
      setLoginMsg('Código generado localmente (servidor no disponible).', 'ok');
    }
    btnReenviar.disabled = false;
  });

  const btnSalir = $a('#btnLogout');
  if (btnSalir) btnSalir.addEventListener('click', ev => { ev.preventDefault(); cerrarSesion(); });

  const formNewUser = $a('#formNewUser');
  if (formNewUser) formNewUser.addEventListener('submit', crearCuenta);

  const formPass = $a('#formPassword');
  if (formPass) formPass.addEventListener('submit', guardarPassword);

  const navU = $a('#navUsuarios');
  if (navU) navU.addEventListener('click', () => setTimeout(renderUsuarios, 0));

  document.querySelectorAll('[data-open-privacy]').forEach(a => a.addEventListener('click', ev => {
    ev.preventDefault();
    const d = document.getElementById('modalPrivacidad');
    if (d) d.showModal();
  }));
  document.querySelectorAll('[data-close-dialog]').forEach(b => b.addEventListener('click', () => {
    const d = b.closest('dialog');
    if (d) d.close();
  }));
}

/* ---------- Arranque ---------- */
(async function authBoot() {
  await authLoad();
  initAuth();
  if (sesionValida()) mostrarApp();
  else mostrarLogin();
  window.authBootDone = true;
})();

/* ============================================================
   ProGanado — Funcionalidad sobre el Modelo Relacional v4.0
   Tablas simuladas en localStorage (12 tablas del MR):
   usuarios, fincas (fija), razas, potreros, bovinos,
   marcaciones, medicamentos, tratamientos_sanitarios,
   eventos_reproductivos, pesajes_leche, entregas_acopio,
   movimientos_potrero
   ============================================================ */
'use strict';

const DB_KEY = 'proGanadoDB_v4';
const $ = sel => document.querySelector(sel);
const $$ = sel => [...document.querySelectorAll(sel)];
const hoy = () => new Date().toISOString().slice(0, 10);
const fechaValida = f => {
  const d = new Date(String(f || '') + 'T12:00:00');
  return isNaN(d.getTime()) ? null : d;
};
const fmtFecha = f => {
  const d = fechaValida(f);
  return d ? d.toLocaleDateString('es-CO', { day: 'numeric', month: 'short' }) : '—';
};
const fmtFechaAnio = f => {
  const d = fechaValida(f);
  return d ? d.toLocaleDateString('es-CO', { day: 'numeric', month: 'short', year: 'numeric' }) : '—';
};
const mesCorto = f => {
  const d = fechaValida(f);
  return d ? d.toLocaleDateString('es-CO', { month: 'short' }).replace('.', '').slice(0, 3).toUpperCase() : '—';
};
const clean = v => String(v == null ? '' : v).trim();
const esc = escapeHtml;
// CSV seguro: entre comillas y evita que una celda se interprete como fórmula en Excel.
const csvSeguro = v => { let s = String(v == null ? '' : v); if (/^[=+\-@]/.test(s)) s = "'" + s; return '"' + s.replaceAll('"', '""') + '"'; };
const uid = p => p + '_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);

/* ---------- Datos semilla (coherentes con el MR) ---------- */
const TODOS_ARETES = '452,458,627,629,635,972,1047,1069,1074,1075,1078,1095,1106,1151,1153,1162,1164,1172,1201,1225,1226,1227,1233,1234,1236,1237,1239,1249,1253,1261,1293,1297,1311,1317,1320,1322,1324,1327,1330,1331,1332,1342,1343,1348,1349,1353,1355,1363,1366,1369,1377,1379,1381,1386,1387,1388,1389,1391,1393,1399,1400,1403,1408,1410,1413,1418,1420,1421,1422,1428,1430,1431,1436,1441,1466,1467,1469,1478,1479,1483,1485,1488,1492,1493,1496,1497,1507,1511,1513,1516,1519,1520,1522,1527,1534,1537,1559,1563,1566,1575,1580,1587,1589,1592,1593,1598,1599,1601,1603,1604,1606,1609,1610,1611,1612,1844'.split(',');

/* Completa el hato con TODAS las vacas fotografiadas (arete real + foto).
   Los datos de cada animal se completan después desde la ficha. */
function completarHato(lista) {
  const yaEstan = new Set(lista.map(b => b.tag));
  for (const tag of TODOS_ARETES) {
    if (yaEstan.has(tag)) continue;
    lista.push({ id_bovino: 'bov_' + tag, name: '', tag: tag, id_raza: '', sexo: '', estado: '', id_potrero: '', birth: '', marca: '', foto: 'assets/ganado/vaca_' + tag + '.jpg' });
  }
  return lista;
}

function seed() {
  const razaBrahman = 'raza_brahman', razaHolstein = 'raza_holstein', razaGyr = 'raza_gyr', razaSim = 'raza_simmental';
  const potNorte = 'pot_norte', potSur = 'pot_sur', potEste = 'pot_este';
  const medAftosa = 'med_aftosa', medOxi = 'med_oxi', medDesp = 'med_desp';
  return {
    razas: [
      { id_raza: razaHolstein, nombre_raza: 'Holstein', descripcion_proposito: 'Lechera especializada' },
      { id_raza: razaBrahman, nombre_raza: 'Brahman', descripcion_proposito: 'Doble propósito' },
      { id_raza: razaGyr, nombre_raza: 'Gyr', descripcion_proposito: 'Lechera tropical' },
      { id_raza: razaSim, nombre_raza: 'Simmental', descripcion_proposito: 'Doble propósito' }
    ],
    potreros: [
      { id_potrero: potNorte, nombre_potrero: 'Potrero Norte', dias_ocupacion: 1, dias_descanso_prv: 35, estado: 'Ocupado', desde: hoy() },
      { id_potrero: potSur, nombre_potrero: 'Potrero Sur', dias_ocupacion: 1, dias_descanso_prv: 35, estado: 'Descanso', desde: hoy() },
      { id_potrero: potEste, nombre_potrero: 'Potrero Este', dias_ocupacion: 2, dias_descanso_prv: 30, estado: 'Libre', desde: null }
    ],
    bovinos: (() => { const l = [
      // Bancas registradas: solo numero de identificacion, demas datos se cargan despues
      { id_bovino: 'bov_1074', name: '', tag: '1074', id_raza: '', sexo: '', estado: '', id_potrero: '', birth: '', marca: '', foto: 'assets/ganado/vaca_1074.jpg' },
      { id_bovino: 'bov_1075', name: '', tag: '1075', id_raza: '', sexo: '', estado: '', id_potrero: '', birth: '', marca: '', foto: 'assets/ganado/vaca_1075.jpg' },
      { id_bovino: 'bov_1078', name: '', tag: '1078', id_raza: '', sexo: '', estado: '', id_potrero: '', birth: '', marca: '', foto: 'assets/ganado/vaca_1078.jpg' },
      { id_bovino: 'bov_1095', name: '', tag: '1095', id_raza: '', sexo: '', estado: '', id_potrero: '', birth: '', marca: '', foto: 'assets/ganado/vaca_1095.jpg' },
      { id_bovino: 'bov_1106', name: '', tag: '1106', id_raza: '', sexo: '', estado: '', id_potrero: '', birth: '', marca: '', foto: 'assets/ganado/vaca_1106.jpg' },
      { id_bovino: 'bov_1151', name: '', tag: '1151', id_raza: '', sexo: '', estado: '', id_potrero: '', birth: '', marca: '', foto: 'assets/ganado/vaca_1151.jpg' },
      { id_bovino: 'bov_1153', name: '', tag: '1153', id_raza: '', sexo: '', estado: '', id_potrero: '', birth: '', marca: '', foto: 'assets/ganado/vaca_1153.jpg' },
      { id_bovino: 'bov_1162', name: '', tag: '1162', id_raza: '', sexo: '', estado: '', id_potrero: '', birth: '', marca: '', foto: 'assets/ganado/vaca_1162.jpg' },
      { id_bovino: 'bov_1164', name: '', tag: '1164', id_raza: '', sexo: '', estado: '', id_potrero: '', birth: '', marca: '', foto: 'assets/ganado/vaca_1164.jpg' },
      { id_bovino: 'bov_1172', name: '', tag: '1172', id_raza: '', sexo: '', estado: '', id_potrero: '', birth: '', marca: '', foto: 'assets/ganado/vaca_1172.jpg' },
      { id_bovino: 'bov_635', name: '', tag: '635', id_raza: '', sexo: '', estado: '', id_potrero: '', birth: '', marca: '', foto: 'assets/ganado/vaca_635.jpg' },
      { id_bovino: 'bov_1201', name: '', tag: '1201', id_raza: '', sexo: '', estado: '', id_potrero: '', birth: '', marca: '', foto: 'assets/ganado/vaca_1201.jpg' }
    ]; return completarHato(l); })(),
    medicamentos: [
      { id_medicamento: medAftosa, nombre_farmaco: 'Vacuna Aftosa', dias_retiro_ica: 0 },
      { id_medicamento: medOxi, nombre_farmaco: 'Oxitetraciclina LA', dias_retiro_ica: 6 },
      { id_medicamento: medDesp, nombre_farmaco: 'Ivermectina 1%', dias_retiro_ica: 8 }
    ],
    tratamientos: [],
    eventos: [],
    pesajes: [],
    entregas: [],
    movimientos: []
  };
}
function diasAtras(n) { const d = new Date(); d.setDate(d.getDate() - n); return d.toISOString().slice(0, 10); }

/* ---------- Persistencia ---------- */
let servidorOK = false;   // true cuando servidor.py responde (datos en la base de datos del servidor)
let guardarTimer = null;
let db = load();
function normalizarDB(parsed) {
  if (!parsed || !Array.isArray(parsed.bovinos)) return null;
  for (const clave of ['razas', 'potreros', 'bovinos', 'medicamentos', 'tratamientos', 'eventos', 'pesajes', 'entregas', 'movimientos', 'contabilidad']) {
    if (!Array.isArray(parsed[clave])) parsed[clave] = [];
  }
  parsed.bovinos = parsed.bovinos.filter(b => b && b.id_bovino);
  // limpieza defensiva: registros huérfanos
  const ids = new Set(parsed.bovinos.map(b => b.id_bovino));
  parsed.tratamientos = parsed.tratamientos.filter(t => t && ids.has(t.id_bovino));
  parsed.eventos = parsed.eventos.filter(e => e && ids.has(e.id_bovino));
  parsed.pesajes = parsed.pesajes.filter(p => p && ids.has(p.id_bovino));
  return parsed;
}
function load() {
  try {
    const raw = localStorage.getItem(DB_KEY);
    if (raw) {
      const parsed = normalizarDB(JSON.parse(raw));
      if (parsed) return parsed;
    }
  } catch (e) { /* datos corruptos: regenerar */ }
  const fresh = seed();
  fresh.contabilidad = [];
  save(fresh);
  return fresh;
}
function save(data) {
  try { localStorage.setItem(DB_KEY, JSON.stringify(data || db)); } catch (e) { /* cuota llena */ }
  if (servidorOK) { clearTimeout(guardarTimer); guardarTimer = setTimeout(guardarEnServidor, 400); }
}
async function guardarEnServidor() {
  try {
    const r = await fetch('/api/db', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(db) });
    if (!r.ok) throw new Error(r.status);
    pintarEstadoDatos('ok');
  } catch (e) { pintarEstadoDatos('error'); }
}
async function sincronizarConServidor() {
  const ctrl = new AbortController();
  const limite = setTimeout(() => ctrl.abort(), 4000);
  try {
    const r = await fetch('/api/db', { cache: 'no-store', signal: ctrl.signal });
    if (!r.ok) throw new Error(r.status);
    const j = await r.json();
    servidorOK = true;
    const remoto = normalizarDB(j.data);
    if (remoto) {
      db = remoto;
      try { localStorage.setItem(DB_KEY, JSON.stringify(db)); } catch (e) {}
      renderAll();
    } else {
      await guardarEnServidor();   // primera vez: sube los datos de este navegador al servidor
    }
    pintarEstadoDatos('ok');
  } catch (e) {
    servidorOK = false;
    pintarEstadoDatos('local');
  } finally {
    clearTimeout(limite);
  }
}
function pintarEstadoDatos(estado) {
  const el = document.getElementById('estadoDatos'); if (!el) return;
  const txt = { ok: '● Datos guardados en el servidor', error: '● Error al guardar en el servidor: revisa que servidor.py esté abierto', local: '● Solo este navegador (abre la app con Iniciar ProGanado.bat para usar el servidor)' }[estado];
  el.textContent = txt; el.dataset.estado = estado;
}

/* ---------- Helpers de dominio ---------- */
const raza = id => (db.razas.find(r => r.id_raza === id) || {}).nombre_raza || '—';
const potrero = id => db.potreros.find(p => p.id_potrero === id);
const bovino = id => db.bovinos.find(b => b.id_bovino === id);
const nombreBov = id => {
  const b = bovino(id);
  return b ? (b.name || 'Animal #' + b.tag) : '—';
};
const etiquetaBovino = b => b ? (b.name ? b.name + ' · #' + b.tag : 'Animal #' + b.tag) : 'Animal';
const medicamento = id => db.medicamentos.find(m => m.id_medicamento === id);

/* Días de retiro pendientes: >0 => leche suspendida */
function retiroPendiente(idBov) {
  let restante = 0;
  for (const t of db.tratamientos.filter(t => t.id_bovino === idBov)) {
    const med = medicamento(t.id_medicamento);
    if (!med || !med.dias_retiro_ica) continue;
    const fin = new Date(t.fecha_tratamiento + 'T12:00:00');
    fin.setDate(fin.getDate() + med.dias_retiro_ica);
    const dias = Math.ceil((fin - new Date()) / 86400000);
    if (dias > 0) restante = Math.max(restante, dias);
  }
  return restante;
}

function edadTexto(birth) {
  const d = fechaValida(birth);
  if (!d) return '—';
  const meses = Math.floor((Date.now() - d.getTime()) / 2592000000);
  if (meses < 0) return '—';
  if (meses < 1) return '<1 mes';
  if (meses < 12) return meses + (meses === 1 ? ' mes' : ' meses');
  const años = Math.floor(meses / 12);
  return años + (años === 1 ? ' año' : ' años');
}

/* ---------- Render: Ganado + cartilla ---------- */
function renderGanado() {
  const q = clean($('#searchAnimals').value).toLowerCase();
  const filtro = $('#categoryFilter').value;
  const lista = db.bovinos.filter(b => (filtro === 'Todos' || b.estado === filtro) && (String(b.name || '') + ' ' + String(b.tag || '')).toLowerCase().includes(q));
  const tb = $('#animalsTable'); tb.replaceChildren();
  for (const b of lista) {
    const tr = document.createElement('tr');
    const retiro = retiroPendiente(b.id_bovino);
    const td1 = document.createElement('td');
    const estado = String(b.estado || '');
    const nombreVisible = b.name || ('Animal #' + b.tag);
    const avatar = b.foto
      ? '<img class="animal-foto" loading="lazy" title="Ver foto grande" src="' + esc(b.foto) + '" alt="' + esc(nombreVisible) + '" />'
      : '<span class="animal-avatar">' + (b.sexo === 'Macho' ? '♂' : estado.includes('Tern') ? '◌' : '♀') + '</span>';
    td1.innerHTML = '<div class="animal-cell">' + avatar + '<strong>' + esc(nombreVisible) + '</strong></div>';
    tr.append(td1);
    if (b.foto) { td1.querySelector('.animal-foto').addEventListener('click', () => abrirFoto(b.id_bovino)); }
    const celdas = [ '#' + b.tag, raza(b.id_raza), b.estado || 'Sin definir', (potrero(b.id_potrero) || {}).nombre_potrero || '—' ];
    for (const val of celdas) { const td = document.createElement('td'); td.textContent = val; tr.append(td); }
    const tdSeg = document.createElement('td');
    tdSeg.innerHTML = retiro > 0 ? '<span class="badge b-red">Retiro ' + retiro + ' d</span>' : '<span class="badge b-green">Al día</span>';
    const tdBtn = document.createElement('td');
    tdBtn.style.whiteSpace = 'nowrap';
    const btn = document.createElement('button'); btn.className = 'mini-btn'; btn.textContent = 'Hoja de vida';
    btn.addEventListener('click', () => { $('#cartillaSelect').value = b.id_bovino; renderCartilla(); document.getElementById('hojaVidaPanel').scrollIntoView({ behavior: 'smooth', block: 'start' }); });
    const btnEdit = document.createElement('button'); btnEdit.className = 'mini-btn'; btnEdit.textContent = '✎'; btnEdit.title = 'Actualizar hoja de vida';
    btnEdit.addEventListener('click', () => abrirEdicion(b.id_bovino));
    const btnDel = document.createElement('button'); btnDel.className = 'mini-btn danger'; btnDel.textContent = '🗑'; btnDel.title = 'Eliminar registro (solo administrador)';
    btnDel.addEventListener('click', () => eliminarBovino(b.id_bovino));
    tdBtn.append(btn, btnEdit);
    if (esAdmin()) tdBtn.append(btnDel); // eliminar: solo administradores
    tr.append(tdSeg, tdBtn); tb.append(tr);
  }
  $('#emptyState').style.display = lista.length ? 'none' : 'block';
  $('#herdCount').textContent = db.bovinos.length;
  $('#metricTotal').textContent = db.bovinos.length;
  const hembras = db.bovinos.filter(b => b.sexo === 'Hembra' && !String(b.estado || '').includes('Tern')).length;
  const machos = db.bovinos.filter(b => b.sexo === 'Macho').length;
  const crias = db.bovinos.filter(b => String(b.estado || '').includes('Tern')).length;
  $('#metricComp').textContent = hembras + ' hembras · ' + machos + ' machos · ' + crias + ' crías';

  // selector de hoja de vida
  const sel = $('#cartillaSelect');
  const previo = sel.value;
  sel.replaceChildren(...db.bovinos.map(b => new Option(etiquetaBovino(b), b.id_bovino)));
  if (previo && db.bovinos.some(b => b.id_bovino === previo)) sel.value = previo;
}

function bloqueHojaVida(titulo, filas) {
  const visibles = filas.filter(([, valor]) => valor !== null && valor !== undefined && String(valor).trim() !== '');
  if (!visibles.length) return '';
  return '<div class="hoja-bloque"><p class="section-eyebrow eyebrow">' + esc(titulo) + '</p><div class="hoja-datos">' +
    visibles.map(([etiqueta, valor]) => '<div><span>' + esc(etiqueta) + '</span><b>' + esc(valor) + '</b></div>').join('') +
    '</div></div>';
}

function renderCartilla() {
  const id = $('#cartillaSelect').value;
  const b = bovino(id);
  const cont = $('#cartillaContent');
  if (!b) { cont.replaceChildren(); return; }
  const tratamientos = db.tratamientos.filter(t => t.id_bovino === id).sort((a, c) => String(c.fecha_tratamiento || '').localeCompare(String(a.fecha_tratamiento || '')));
  const eventos = db.eventos.filter(e => e.id_bovino === id).sort((a, c) => String(c.fecha_evento || '').localeCompare(String(a.fecha_evento || '')));
  const pesajes = db.pesajes.filter(p => p.id_bovino === id).sort((a, c) => (String(c.fecha_pesaje || '') + String(c.hora_pesaje || '')).localeCompare(String(a.fecha_pesaje || '') + String(a.hora_pesaje || '')));
  const retiro = retiroPendiente(id);
  const situacion = clean(b.situacion);
  const sitBadge = situacion
    ? '<span class="badge ' + (situacion === 'Enfermo' ? 'b-red' : situacion === 'Venta' || situacion === 'Descarte' ? 'b-amber' : 'b-green') + '">' + esc(situacion) + '</span>'
    : '—';
  const desdeParto = b.ultimo_parto && fechaValida(b.ultimo_parto) ? b.ultimo_parto : '';
  const pesajesLactancia = desdeParto ? pesajes.filter(p => String(p.fecha_pesaje || '') >= desdeParto) : pesajes;
  const totalLeche = pesajesLactancia.reduce((s, p) => s + (Number(p.litros_obtenidos) || 0), 0);
  const diasLactancia = desdeParto ? Math.max(0, diasDesde(desdeParto)) : '';
  const filasManejo = [
    ['Nacimiento', b.birth ? fmtFechaAnio(b.birth) : ''],
    ['Padre', clean(b.padre)],
    ['Madre', clean(b.madre)],
    ['Color', clean(b.color)],
    ['Lote / grupo', clean(b.lote)],
    ['Hierro', clean(b.hierro)],
    ['Chip', clean(b.chip)],
    ['Procedencia', clean(b.procedencia)]
  ];
  const filasRepro = [
    ['Último parto', b.ultimo_parto ? fmtFechaAnio(b.ultimo_parto) : ''],
    ['Último celo', b.ultimo_celo ? fmtFechaAnio(b.ultimo_celo) : ''],
    ['Fecha de preñez', b.fecha_prenez ? fmtFechaAnio(b.fecha_prenez) : ''],
    ['Parto esperado', b.parto_esperado ? fmtFechaAnio(b.parto_esperado) : ''],
    ['Reproductor / toro', clean(b.reproductor)],
    ['Tipo de servicio', clean(b.tipo_servicio)],
    ['N.º de servicios', b.servicios === '' || b.servicios == null ? '' : String(b.servicios)],
    ['N.º de partos', b.partos === '' || b.partos == null ? '' : String(b.partos)],
    ['Abortos', b.abortos === '' || b.abortos == null ? '' : String(b.abortos)]
  ];
  const filasPeso = [
    ['Peso actual', b.peso_kg === '' || b.peso_kg == null ? '' : b.peso_kg + ' kg'],
    ['Fecha del pesaje', b.peso_fecha ? fmtFechaAnio(b.peso_fecha) : ''],
    ['Condición corporal', b.condicion_corporal === '' || b.condicion_corporal == null ? '' : b.condicion_corporal + ' / 5'],
    ['Leche registrada', pesajes.length ? totalLeche.toLocaleString('es-CO', { maximumFractionDigits: 1 }) + ' L' : ''],
    ['Controles lácteos', pesajes.length ? String(pesajes.length) : ''],
    ['Días de lactancia', diasLactancia === '' ? '' : diasLactancia + ' días']
  ];
  const bloques = bloqueHojaVida('Genealogía y manejo', filasManejo) +
    bloqueHojaVida('Reproducción', filasRepro) +
    bloqueHojaVida('Peso y salud', filasPeso);
  const notasHoja = [
    b.notas_salud ? ['Notas de salud', b.notas_salud] : null,
    b.observaciones ? ['Observaciones', b.observaciones] : null
  ].filter(Boolean);
  const notaHtml = notasHoja.map(([titulo, texto]) => '<div class="hoja-nota"><span>' + esc(titulo) + '</span><p>' + esc(texto) + '</p></div>').join('');
  const contenidoAmpliado = bloques + notaHtml ||
    '<div class="hoja-vacia">Aún no hay datos ampliados de este animal. Usa <b>Actualizar datos</b> para completar genealogía, reproducción, peso y salud.</div>';
  cont.innerHTML =
    '<div class="cartilla-head">' + (b.foto ? '<img src="' + esc(b.foto) + '" alt="' + esc(b.name || 'Animal #' + b.tag) + '" />' : '') + '<div><strong>' + esc(b.name || 'Animal #' + b.tag) + '</strong><span>Hoja de vida · #' + esc(b.tag) + ' · ' + esc(raza(b.id_raza)) + '</span></div></div>' +
    '<div class="kpi-list">' +
    '<div><span>Raza</span><b>' + esc(raza(b.id_raza)) + '</b></div>' +
    '<div><span>Edad</span><b>' + edadTexto(b.birth) + '</b></div>' +
    '<div><span>Estado fisiológico</span><b>' + esc(b.estado || 'Sin definir') + '</b></div>' +
    '<div><span>Situación</span><b>' + sitBadge + '</b></div>' +
    '<div><span>Potrero</span><b>' + esc((potrero(b.id_potrero) || {}).nombre_potrero || '—') + '</b></div>' +
    '<div><span>Identificación</span><b>' + esc(b.marca || 'Sin marca registrada') + '</b></div>' +
    '<div><span>Seguimiento médico</span><b>' + (retiro > 0 ? '<span class="badge b-red">LECHE SUSPENDIDA · retiro ' + retiro + ' días</span>' : '<span class="badge b-green">Sin retiro activo</span>') + '</b></div>' +
    '</div>' +
    contenidoAmpliado +
    '<p class="section-eyebrow eyebrow">Tratamientos y vacunas (' + tratamientos.length + ')</p>' +
    (tratamientos.length ? '<div class="reto-list">' + tratamientos.map(t => {
      const med = medicamento(t.id_medicamento) || {};
      const r = retiroDeTrat(t);
      return '<div class="reto"><span class="calendar">' + esc(String(t.fecha_tratamiento || '').slice(8)) + '<br><b>' + mesCorto(t.fecha_tratamiento) + '</b></span><div><strong>' + esc(t.tipo_procedimiento) + ' · ' + esc(med.nombre_farmaco || '?') + '</strong><p>Dosis ' + esc(t.dosis_ml) + ' ml' + (t.nota ? ' · ' + esc(t.nota) : '') + '</p></div><span class="spacer">' + (r > 0 ? '<span class="badge b-red">Leche suspendida ' + r + ' d</span>' : '<span class="badge b-green">Retiro cumplido</span>') + '</span></div>';
    }).join('') + '</div>' : '<p class="empty" style="display:block">Sin tratamientos registrados.</p>') +
    '<p class="section-eyebrow eyebrow">Eventos reproductivos (' + eventos.length + ')</p>' +
    (eventos.length ? '<div class="reto-list">' + eventos.map(e => '<div class="reto"><span class="calendar">' + esc(String(e.fecha_evento || '').slice(8)) + '<br><b>' + mesCorto(e.fecha_evento) + '</b></span><div><strong>' + esc(e.tipo_evento) + '</strong><p>' + esc(e.nota || '') + '</p></div><span class="spacer">' + (e.dias_abiertos_calc ? '<span class="badge b-amber">' + diasDesde(e.fecha_evento) + ' d abiertos</span>' : '') + '</span></div>').join('') + '</div>' : '<p class="empty" style="display:block">Sin eventos reproductivos.</p>') +
    '<p class="section-eyebrow eyebrow">Últimos pesajes (' + pesajes.length + ')</p>' +
    (pesajes.length ? '<div class="reto-list">' + pesajes.slice(0, 5).map(p => '<div class="reto"><span class="calendar">' + esc(String(p.fecha_pesaje || '').slice(8)) + '<br><b>' + mesCorto(p.fecha_pesaje) + '</b></span><div><strong>' + esc(p.litros_obtenidos) + ' L</strong><p>Ordeño de las ' + esc(p.hora_pesaje) + '</p></div></div>').join('') + '</div>' : '<p class="empty" style="display:block">Sin pesajes.</p>');
}
function retiroDeTrat(t) {
  const med = medicamento(t.id_medicamento);
  if (!med || !med.dias_retiro_ica) return 0;
  const fin = new Date(t.fecha_tratamiento + 'T12:00:00');
  fin.setDate(fin.getDate() + med.dias_retiro_ica);
  return Math.max(0, Math.ceil((fin - new Date()) / 86400000));
}
function diasDesde(f) {
  const d = fechaValida(f);
  return d ? Math.floor((Date.now() - d.getTime()) / 86400000) : 0;
}

/* ---------- Render: Salud ---------- */
function renderSalud() {
  const tb = $('#tratamientosTable'); tb.replaceChildren();
  const lista = [...db.tratamientos].sort((a, b) => String(b.fecha_tratamiento || '').localeCompare(String(a.fecha_tratamiento || '')));
  let enRetiro = 0, activos = 0;
  for (const t of lista) {
    const med = medicamento(t.id_medicamento) || {};
    const r = retiroDeTrat(t);
    if (r > 0) { enRetiro++; activos++; }
    const tr = document.createElement('tr');
    tr.innerHTML = '<td><strong>' + esc(nombreBov(t.id_bovino)) + '</strong></td><td>' + esc(t.tipo_procedimiento) + '</td><td>' + esc(med.nombre_farmaco || '?') + '</td><td>' + fmtFecha(t.fecha_tratamiento) + '</td><td>' + esc(t.dosis_ml) + ' ml</td><td>' + esc(med.dias_retiro_ica || 0) + ' días</td><td>' + (r > 0 ? '<span class="badge b-red">Retiro ' + r + ' d</span>' : '<span class="badge b-green">Cumplido</span>') + '</td>';
    tb.append(tr);
  }
  $('#emptyTrat').style.display = lista.length ? 'none' : 'block';
  $('#saludRetiro').textContent = enRetiro;
  $('#saludActivos').textContent = activos;
  $('#saludTotal').textContent = lista.length;
  $('#metricRetiro').textContent = enRetiro;
  const mt = $('#medicamentosTable'); mt.replaceChildren();
  for (const m of db.medicamentos) {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td><strong>' + esc(m.nombre_farmaco) + '</strong></td><td>' + (m.dias_retiro_ica ? '<span class="badge b-amber">' + esc(m.dias_retiro_ica) + ' días</span>' : '<span class="badge b-green">Sin retiro</span>') + '</td>';
    mt.append(tr);
  }
}

/* ---------- Render: Reproducción ---------- */
function renderRepro() {
  const tb = $('#reproTable'); tb.replaceChildren();
  const lista = [...db.eventos].sort((a, b) => String(b.fecha_evento || '').localeCompare(String(a.fecha_evento || '')));
  for (const e of lista.slice(0, 12)) {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td><strong>' + esc(nombreBov(e.id_bovino)) + '</strong></td><td>' + esc(e.tipo_evento) + '</td><td>' + fmtFecha(e.fecha_evento) + '</td><td>' + (e.dias_abiertos_calc ? diasDesde(e.fecha_evento) + ' d' : '—') + '</td><td>' + esc(e.nota || '') + '</td>';
    tb.append(tr);
  }
  $('#emptyRepro').style.display = lista.length ? 'none' : 'block';
  const gestantes = new Set(db.eventos.filter(e => e.tipo_evento === 'Inseminación' && diasDesde(e.fecha_evento) <= 120 && !db.eventos.some(o => o.id_bovino === e.id_bovino && o.tipo_evento === 'Parto' && o.fecha_evento > e.fecha_evento)).map(e => e.id_bovino));
  $('#reproGest').textContent = gestantes.size;
  $('#metricGest').textContent = gestantes.size;
  const proxParto = [...gestantes].map(id => { const ins = db.eventos.filter(e => e.id_bovino === id && e.tipo_evento === 'Inseminación').sort((a, b) => b.fecha_evento.localeCompare(a.fecha_evento))[0]; return ins ? fmtFecha(sumarDias(ins.fecha_evento, 283)) : null; }).filter(Boolean)[0];
  $('#metricGestInfo').textContent = proxParto ? 'Próximo parto estimado: ' + proxParto : 'Sin gestaciones confirmadas';
  $('#reproGestInfo').textContent = proxParto ? 'Parto estimado: ' + proxParto : '—';
  const celos = db.eventos.filter(e => e.tipo_evento === 'Celo Observable' && diasDesde(e.fecha_evento) <= 25);
  $('#reproCelos').textContent = new Set(celos.map(e => e.id_bovino)).size;
  const partos = db.eventos.filter(e => e.tipo_evento === 'Parto' && String(e.fecha_evento || '').slice(0, 4) === String(new Date().getFullYear()));
  $('#reproPartos').textContent = partos.length;
  $('#reproPartosInfo').textContent = partos.length ? 'Último: ' + fmtFecha(partos.sort((a, b) => b.fecha_evento.localeCompare(a.fecha_evento))[0].fecha_evento) : '—';
}
function sumarDias(f, n) { const d = fechaValida(f); if (!d) return ''; d.setDate(d.getDate() + n); return d.toISOString().slice(0, 10); }

/* ---------- Render: Producción ---------- */
function renderProduccion() {
  const litrosHoy = db.pesajes.filter(p => p.fecha_pesaje === hoy()).reduce((s, p) => s + Number(p.litros_obtenidos), 0);
  $('#prodHoy').textContent = litrosHoy.toFixed(1);
  $('#metricLeche').innerHTML = litrosHoy.toFixed(1) + ' <em>L</em>';
  const mesActual = hoy().slice(0, 7);
  const litrosMes = db.pesajes.filter(p => p.fecha_pesaje.startsWith(mesActual)).reduce((s, p) => s + Number(p.litros_obtenidos), 0);
  $('#prodMes').textContent = litrosMes.toFixed(0);
  const ult7 = db.pesajes.filter(p => diasDesde(p.fecha_pesaje) < 7);
  const vacasOrdeño = db.bovinos.filter(b => b.estado === 'En Ordeño').length || 1;
  $('#prodProm').textContent = (ult7.reduce((s, p) => s + Number(p.litros_obtenidos), 0) / 7).toFixed(1);
  $('#prodProm').nextElementSibling.textContent = 'Litros/día · ' + vacasOrdeño + ' vacas en ordeño';
  $('#metricLecheInfo').textContent = litrosHoy ? 'Promedio ' + (litrosHoy / vacasOrdeño).toFixed(1) + ' L/vaca' : 'Sin registro de hoy';

  const tp = $('#pesajesTable'); tp.replaceChildren();
  const pesajes = [...db.pesajes].sort((a, b) => (String(b.fecha_pesaje || '') + String(b.hora_pesaje || '')).localeCompare(String(a.fecha_pesaje || '') + String(a.hora_pesaje || ''))).slice(0, 10);
  for (const p of pesajes) {
    const tr = document.createElement('tr');
    const bloqueada = retiroPendiente(p.id_bovino) > 0;
    tr.innerHTML = '<td><strong>' + esc(nombreBov(p.id_bovino)) + '</strong>' + (bloqueada ? ' <span class="badge b-red">retiro</span>' : '') + '</td><td>' + fmtFecha(p.fecha_pesaje) + '</td><td>' + esc(p.hora_pesaje) + '</td><td>' + esc(p.litros_obtenidos) + ' L</td>';
    tp.append(tr);
  }
  $('#emptyPesajes').style.display = pesajes.length ? 'none' : 'block';

  const te = $('#entregasTable'); te.replaceChildren();
  const entregas = [...db.entregas].sort((a, b) => String(b.fecha_entrega || '').localeCompare(String(a.fecha_entrega || ''))).slice(0, 10);
  for (const e of entregas) {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td>' + fmtFecha(e.fecha_entrega) + '</td><td>' + esc(e.litros_totales) + ' L</td><td>$ ' + Number(e.valor_bruto_est || 0).toLocaleString('es-CO') + '</td><td>' + (Number(e.recuento_ufc) <= 100000 ? '<span class="badge b-green">' + Number(e.recuento_ufc || 0).toLocaleString('es-CO') + '</span>' : '<span class="badge b-amber">' + Number(e.recuento_ufc || 0).toLocaleString('es-CO') + '</span>') + '</td>';
    te.append(tr);
  }
  $('#emptyEntregas').style.display = entregas.length ? 'none' : 'block';
}

/* ---------- Render: Potreros PRV ---------- */
function renderPotreros() {
  const cont = $('#potrerosList'); cont.replaceChildren();
  for (const p of db.potreros) {
    const div = document.createElement('div'); div.className = 'reto';
    const badge = p.estado === 'Ocupado' ? 'b-blue' : p.estado === 'Descanso' ? 'b-amber' : 'b-gray';
    div.innerHTML = '<span class="calendar">▣</span><div><strong>' + esc(p.nombre_potrero) + '</strong><p>Ocupación ' + esc(p.dias_ocupacion) + ' d · descanso PRV ' + esc(p.dias_descanso_prv) + ' d' + (p.desde ? ' · desde ' + fmtFecha(p.desde) : '') + '</p></div><span class="spacer"><span class="badge ' + badge + '">' + esc(p.estado) + '</span></span>';
    const btn = document.createElement('button'); btn.className = 'mini-btn';
    btn.textContent = p.estado === 'Ocupado' ? 'Liberar' : 'Ocupar';
    btn.addEventListener('click', () => {
      p.estado = p.estado === 'Ocupado' ? 'Descanso' : 'Ocupado';
      p.desde = hoy();
      db.movimientos.unshift({ id_mov: uid('mov'), id_potrero: p.id_potrero, accion: p.estado === 'Ocupado' ? 'Entrada' : 'Salida', fecha: hoy(), cantidad: db.bovinos.filter(b => b.id_potrero === p.id_potrero).length });
      save(); renderPotreros(); renderMovs();
    });
    div.querySelector('.spacer').append(btn);
    cont.append(div);
  }
  $('#potrerosTotal').textContent = db.potreros.length;
  $('#potrerosOcup').textContent = db.potreros.filter(p => p.estado === 'Ocupado').length;
  $('#potrerosDesc').textContent = db.potreros.filter(p => p.estado === 'Descanso').length;
  $('#potrerosInfo').textContent = 'PRV ' + Math.round(db.potreros.reduce((s, p) => s + p.dias_descanso_prv, 0) / (db.potreros.length || 1)) + ' d descanso promedio';

  // sincronizar selects de potrero
  const opts = db.potreros.map(p => new Option(p.nombre_potrero, p.id_potrero));
  $('#potreroSelect').replaceChildren(new Option('Sin potrero', ''), ...opts);
  $('#movPotreroSelect').replaceChildren(...opts);
}

function renderMovs() {
  const tb = $('#movsTable'); tb.replaceChildren();
  const lista = [...db.movimientos].sort((a, b) => String(b.fecha || '').localeCompare(String(a.fecha || ''))).slice(0, 12);
  for (const m of lista) {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td>' + fmtFecha(m.fecha) + '</td><td>' + esc(m.cantidad) + ' animales</td><td>' + esc((potrero(m.id_potrero) || {}).nombre_potrero || '—') + '</td><td>' + (m.accion === 'Entrada' ? '<span class="badge b-blue">Entrada</span>' : '<span class="badge b-amber">Salida</span>') + '</td>';
    tb.append(tr);
  }
  $('#emptyMovs').style.display = lista.length ? 'none' : 'block';
}

/* ---------- Render: Inicio (agenda, donut, entrega, actividad) ---------- */
function renderInicio() {
  // Agenda: retiros por vencer + celos + partos estimados
  const agenda = [];
  for (const b of db.bovinos) {
    const r = retiroPendiente(b.id_bovino);
    if (r > 0) agenda.push({ fecha: sumarDias(hoy(), r), titulo: 'Fin de retiro · ' + b.name, sub: 'Leche apta para acopio', dias: r, tipo: 'red' });
  }
  for (const e of db.eventos.filter(e => e.tipo_evento === 'Celo Observable' && diasDesde(e.fecha_evento) <= 25)) {
    agenda.push({ fecha: sumarDias(e.fecha_evento, 21), titulo: 'Reviso celo · ' + nombreBov(e.id_bovino), sub: 'Ciclo de 21 días', dias: diasDesde(sumarDias(e.fecha_evento, 21)), tipo: 'amber' });
  }
  for (const e of db.eventos.filter(e => e.tipo_evento === 'Inseminación')) {
    const parto = sumarDias(e.fecha_evento, 283);
    const d = diasDesde(parto);
    if (d <= -1) agenda.push({ fecha: parto, titulo: 'Parto estimado · ' + nombreBov(e.id_bovino), sub: 'Gestación día ' + diasDesde(e.fecha_evento), dias: -d, tipo: 'blue' });
  }
  agenda.sort((a, b) => a.dias - b.dias);
  const ag = $('#agendaList');
  ag.innerHTML = agenda.slice(0, 5).map(a => {
    const dia = new Date(a.fecha + 'T12:00:00');
    const tag = a.dias <= 0 ? '<span class="tag red-tag">Hoy</span>' : '<span class="tag">En ' + a.dias + ' d</span>';
    return '<div class="reminder"><span class="calendar' + (a.dias <= 0 ? ' urgent' : '') + '">' + dia.getDate() + '<br><b>' + dia.toLocaleDateString('es-CO', { month: 'short' }).slice(0, 3).toUpperCase() + '</b></span><div><strong>' + esc(a.titulo) + '</strong><p>' + esc(a.sub) + '</p></div>' + tag + '</div>';
  }).join('') || '<p class="empty" style="display:block">Sin eventos próximos.</p>';

  // Donut composición
  const hembras = db.bovinos.filter(b => b.sexo === 'Hembra' && !String(b.estado || '').includes('Tern')).length;
  const crias = db.bovinos.filter(b => String(b.estado || '').includes('Tern')).length;
  const machos = db.bovinos.filter(b => b.sexo === 'Macho').length;
  const total = db.bovinos.length || 1;
  const p1 = Math.round(hembras / total * 100), p2 = Math.round(crias / total * 100);
  $('#donut').style.background = 'conic-gradient(#50966f 0 ' + p1 + '%,#c8ae59 ' + p1 + '% ' + (p1 + p2) + '%,#9cb2c7 ' + (p1 + p2) + '% 100%)';
  $('#donutTotal').textContent = db.bovinos.length;
  $('#donutLegend').innerHTML = '<li><i class="female"></i> Hembras adultas <b>' + hembras + '</b></li><li><i class="calf"></i> Crías <b>' + crias + '</b></li><li><i class="male"></i> Machos <b>' + machos + '</b></li>';

  // Última entrega
  const ent = [...db.entregas].sort((a, b) => String(b.fecha_entrega || '').localeCompare(String(a.fecha_entrega || '')))[0];
  $('#ultimaEntrega').innerHTML = ent ?
    '<div class="kpi-list"><div><span>Fecha</span><b>' + fmtFecha(ent.fecha_entrega) + '</b></div><div><span>Litros</span><b>' + ent.litros_totales + ' L</b></div><div><span>Valor bruto</span><b>$ ' + Number(ent.valor_bruto_est).toLocaleString('es-CO') + '</b></div><div><span>Calidad UFC</span><b>' + (ent.recuento_ufc <= 100000 ? '<span class="badge b-green">Apta Colanta</span>' : '<span class="badge b-amber">Revisar</span>') + '</b></div></div>'
    : '<p class="empty" style="display:block">Sin entregas registradas.</p>';

  // Actividad reciente
  const acts = [];
  for (const t of [...db.tratamientos].sort((a, b) => String(b.fecha_tratamiento || '').localeCompare(String(a.fecha_tratamiento || ''))).slice(0, 2)) acts.push({ icon: '✚', t: t.tipo_procedimiento, s: nombreBov(t.id_bovino) + ' · ' + ((medicamento(t.id_medicamento) || {}).nombre_farmaco || ''), f: fmtFecha(t.fecha_tratamiento) });
  for (const p of [...db.pesajes].sort((a, b) => (String(b.fecha_pesaje || '') + String(b.hora_pesaje || '')).localeCompare(String(a.fecha_pesaje || '') + String(a.hora_pesaje || ''))).slice(0, 1)) acts.push({ icon: '◒', t: 'Pesaje de leche', s: nombreBov(p.id_bovino) + ' · ' + p.litros_obtenidos + ' L', f: fmtFecha(p.fecha_pesaje) });
  for (const m of [...db.movimientos].sort((a, b) => String(b.fecha || '').localeCompare(String(a.fecha || ''))).slice(0, 1)) acts.push({ icon: '↔', t: 'Pastoreo · ' + m.accion, s: (potrero(m.id_potrero) || {}).nombre_potrero + ' · ' + m.cantidad + ' animales', f: fmtFecha(m.fecha) });
  $('#actividadReciente').innerHTML = acts.slice(0, 4).map(a => '<div class="activity-row"><span class="activity-icon">' + a.icon + '</span><div><strong>' + esc(a.t) + '</strong><p>' + esc(a.s) + '</p></div><time>' + esc(a.f) + '</time></div>').join('');
}

/* ---------- Selectores dependientes ---------- */
function fillSelects() {
  $('#razaSelect').replaceChildren(new Option('Sin definir', ''), ...db.razas.map(r => new Option(r.nombre_raza, r.id_raza)));
  $('#tratBovinoSelect').replaceChildren(...db.bovinos.map(b => new Option(etiquetaBovino(b), b.id_bovino)));
  $('#evBovinoSelect').replaceChildren(...db.bovinos.map(b => new Option(etiquetaBovino(b), b.id_bovino)));
  $('#pesBovinoSelect').replaceChildren(...db.bovinos.filter(b => b.estado === 'En Ordeño').map(b => new Option(etiquetaBovino(b), b.id_bovino)));
  $('#tratMedSelect').replaceChildren(...db.medicamentos.map(m => new Option(m.nombre_farmaco + ' (retiro ' + m.dias_retiro_ica + ' d)', m.id_medicamento)));
  $('#cartillaSelect').replaceChildren(...db.bovinos.map(b => new Option(etiquetaBovino(b), b.id_bovino)));
  $('#potreroSelect').replaceChildren(new Option('Sin potrero', ''), ...db.potreros.map(p => new Option(p.nombre_potrero, p.id_potrero)));
}

/* ---------- Lightbox de foto ---------- */
function abrirFoto(id) {
  const b = bovino(id); if (!b || !b.foto) return;
  $('#fotoGrande').src = b.foto;
  $('#fotoNombre').textContent = b.name || ('Animal #' + b.tag);
  $('#fotoNombre').dataset.id = id;
  const r = retiroPendiente(id);
  $('#fotoDetalle').textContent = '#' + b.tag + ' · ' + raza(b.id_raza) + ' · ' + (b.estado || 'Sin definir') + (r > 0 ? ' · ⚠ retiro ' + r + ' d' : '');
  document.getElementById('fotoModal').showModal();
}
$('#fotoClose').addEventListener('click', () => document.getElementById('fotoModal').close());
$('#fotoCartilla').addEventListener('click', () => { const id = $('#fotoNombre').dataset.id; document.getElementById('fotoModal').close(); $('#cartillaSelect').value = id; renderCartilla(); document.getElementById('hojaVidaPanel').scrollIntoView({ behavior: 'smooth', block: 'start' }); });

/* ---------- Foto del animal ---------- */
// Las fotos nuevas se guardan en el almacén binario del servidor con prefijo bov_.
// Si el servidor no está disponible, se guarda una versión comprimida como data URL.
let fotoAnimalActual = '';
let fotoPreviewObjectURL = null;

function liberarFotoPreview() {
  if (fotoPreviewObjectURL) {
    URL.revokeObjectURL(fotoPreviewObjectURL);
    fotoPreviewObjectURL = null;
  }
}

function pintarFotoPreview(src) {
  liberarFotoPreview();
  const img = $('#fotoBovinoPreview');
  const vacio = $('#fotoBovinoSinFoto');
  if (src) {
    img.src = src;
    img.hidden = false;
    vacio.hidden = true;
  } else {
    img.removeAttribute('src');
    img.hidden = true;
    vacio.hidden = false;
  }
}

function mostrarArchivoFoto(file) {
  liberarFotoPreview();
  fotoPreviewObjectURL = URL.createObjectURL(file);
  const img = $('#fotoBovinoPreview');
  img.src = fotoPreviewObjectURL;
  img.hidden = false;
  $('#fotoBovinoSinFoto').hidden = true;
}

function restaurarFotoActual() {
  $('#quitarFotoBovino').checked = false;
  pintarFotoPreview(fotoAnimalActual);
  $('#fotoBovinoQuitarLabel').hidden = !fotoAnimalActual;
}

function prepararFotoBovino(b) {
  fotoAnimalActual = (b && b.foto) || '';
  const form = $('#formBovino');
  if (form.elements.foto) form.elements.foto.value = '';
  restaurarFotoActual();
}

function claveFotoAnimal(url) {
  const m = String(url || '').match(/^\/api\/factura\/([A-Za-z0-9_\-]{1,80})(?:\?|$)/);
  return m ? m[1] : '';
}

async function fotoAnimalGuardar(id, blob) {
  const clave = 'bov_' + String(id).replace(/^bov_/, '');
  if (servidorOK) {
    try {
      const r = await fetch('/api/factura/' + encodeURIComponent(clave), {
        method: 'PUT', headers: { 'Content-Type': 'image/jpeg' }, body: blob
      });
      if (r.ok) return '/api/factura/' + encodeURIComponent(clave) + '?v=' + Date.now();
    } catch (e) { /* se usa el respaldo local */ }
  }
  return blobADataURL(blob);
}

function blobADataURL(blob) {
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload = () => res(r.result);
    r.onerror = () => rej(new Error('No se pudo preparar la imagen.'));
    r.readAsDataURL(blob);
  });
}

async function fotoAnimalBorrar(url) {
  const clave = claveFotoAnimal(url);
  if (!clave || !servidorOK) return;
  await fetch('/api/factura/' + encodeURIComponent(clave), { method: 'DELETE' }).catch(() => {});
}

$('#fotoBovinoInput').addEventListener('change', e => {
  const archivo = e.target.files && e.target.files[0];
  if (!archivo) { restaurarFotoActual(); return; }
  if (archivo.type && !archivo.type.startsWith('image/')) {
    e.target.value = '';
    restaurarFotoActual();
    alert('Solo se aceptan imágenes (JPG, PNG o WEBP).');
    return;
  }
  if (archivo.size > 15 * 1024 * 1024) {
    e.target.value = '';
    restaurarFotoActual();
    alert('La foto supera 15 MB. Usa una imagen más pequeña.');
    return;
  }
  $('#quitarFotoBovino').checked = false;
  mostrarArchivoFoto(archivo);
  $('#fotoBovinoQuitarLabel').hidden = false;
});

$('#quitarFotoBovino').addEventListener('change', e => {
  if (e.target.checked) {
    $('#fotoBovinoInput').value = '';
    pintarFotoPreview('');
  } else {
    restaurarFotoActual();
  }
});

document.getElementById('modalBovino').addEventListener('close', liberarFotoPreview);

/* ---------- Editar / eliminar animal ---------- */
let idEditando = null;
function abrirEdicion(id) {
  const b = bovino(id); if (!b) return;
  idEditando = id;
  fillSelects();
  $('#eyebrowBovino').textContent = 'Hoja de vida';
  $('#tituloBovino').textContent = 'Actualizar · ' + (b.name ? b.name + ' · #' + b.tag : 'Animal #' + b.tag);
  const f = $('#formBovino');
  const campos = ['name', 'tag', 'marca', 'chip', 'color', 'hierro', 'lote', 'situacion', 'procedencia',
    'padre', 'madre', 'ultimo_parto', 'ultimo_celo', 'fecha_prenez', 'parto_esperado', 'reproductor',
    'tipo_servicio', 'servicios', 'partos', 'abortos', 'peso_kg', 'peso_fecha', 'condicion_corporal',
    'notas_salud', 'observaciones'];
  for (const campo of campos) {
    if (f.elements[campo]) f.elements[campo].value = b[campo] == null ? '' : b[campo];
  }
  f.elements.raza.value = b.id_raza || '';
  f.elements.sexo.value = b.sexo || '';
  f.elements.estado.value = b.estado || '';
  f.elements.potrero.value = b.id_potrero || '';
  f.elements.birth.value = b.birth || '';
  prepararFotoBovino(b);
  document.getElementById('modalBovino').showModal();
}
async function eliminarBovino(id) {
  const b = bovino(id); if (!b) return;
  const relacionados = db.tratamientos.filter(t => t.id_bovino === id).length + db.eventos.filter(e => e.id_bovino === id).length + db.pesajes.filter(p => p.id_bovino === id).length;
  const etiqueta = b.name ? b.name + ' (#' + b.tag + ')' : 'Animal #' + b.tag;
  const msg = '¿Eliminar el registro de ' + etiqueta + '?' + (relacionados ? '\n\nTambién se borrarán ' + relacionados + ' registro(s) médicos y de producción asociados.' : '');
  if (!confirm(msg)) return;
  await fotoAnimalBorrar(b.foto);
  db.bovinos = db.bovinos.filter(x => x.id_bovino !== id);
  db.tratamientos = db.tratamientos.filter(t => t.id_bovino !== id);
  db.eventos = db.eventos.filter(e => e.id_bovino !== id);
  db.pesajes = db.pesajes.filter(p => p.id_bovino !== id);
  save(); renderAll();
}

/* ---------- Modales ---------- */
function openModal(id) {
  fillSelects();
  if (id === 'modalBovino') {
    idEditando = null;
    $('#eyebrowBovino').textContent = 'Nuevo registro';
    $('#tituloBovino').textContent = 'Registrar animal';
    const f = $('#formBovino');
    f.reset();
    f.elements.sexo.value = 'Hembra';
    f.elements.estado.value = 'En Ordeño';
    f.elements.situacion.value = 'Activo';
    prepararFotoBovino(null);
  }
  const d = document.getElementById(id); if (id === 'modalTratamiento') avisoTrat(); if (id === 'modalPesaje') avisoPesaje(); d.showModal();
}
$$('[data-open-modal]').forEach(btn => btn.addEventListener('click', () => openModal(btn.dataset.openModal)));
$('#btnEditarHojaVida').addEventListener('click', () => {
  const id = $('#cartillaSelect').value;
  if (!id) { alert('No hay animales registrados.'); return; }
  abrirEdicion(id);
});

function avisoTrat() {
  const id = $('#tratBovinoSelect').value, medId = $('#tratMedSelect').value;
  const med = medicamento(medId);
  $('#tratAviso').textContent = med && med.dias_retiro_ica ? '⚠ ' + ((bovino(id) || {}).name || 'El animal') + ' no podrá aportar leche durante ' + med.dias_retiro_ica + ' días (retiro ICA).' : 'Sin días de retiro para este medicamento.';
}
$('#tratBovinoSelect').addEventListener('change', avisoTrat);
$('#tratMedSelect').addEventListener('change', avisoTrat);
function avisoPesaje() {
  const id = $('#pesBovinoSelect').value;
  const r = retiroPendiente(id);
  $('#pesAviso').textContent = r > 0 ? '⚠ ' + nombreBov(id) + ' está en retiro (' + r + ' d): esa leche NO debe enviarse a Colanta.' : '';
}
$('#pesBovinoSelect').addEventListener('change', avisoPesaje);

/* ---------- Formularios ---------- */
let guardandoBovino = false;
$('#formBovino').addEventListener('submit', async e => {
  e.preventDefault();
  if (guardandoBovino) return;
  const form = e.target;
  const f = Object.fromEntries(new FormData(form));
  const tag = clean(f.tag);
  if (!tag) { alert('El arete es obligatorio.'); return; }
  if (db.bovinos.some(b => clean(b.tag).toLowerCase() === tag.toLowerCase() && b.id_bovino !== idEditando)) { alert('Ese número de arete ya existe.'); return; }

  const archivo = form.elements.foto.files[0];
  if (archivo && archivo.type && !archivo.type.startsWith('image/')) return alert('Solo se aceptan imágenes (JPG, PNG o WEBP).');
  if (archivo && archivo.size > 15 * 1024 * 1024) return alert('La foto supera 15 MB. Usa una imagen más pequeña.');

  const numero = valor => valor === '' || valor == null ? '' : Number(valor);
  const bActual = idEditando ? bovino(idEditando) : null;
  const idBov = idEditando || uid('bov');
  const boton = form.querySelector('button[value=default]');
  const textoBoton = boton ? boton.textContent : '';
  guardandoBovino = true;
  if (boton) { boton.disabled = true; boton.textContent = 'Guardando…'; }

  try {
    let foto = bActual ? (bActual.foto || '') : '';
    if (archivo) {
      const blob = await comprimirImagen(archivo, 1200, 0.78);
      foto = await fotoAnimalGuardar(idBov, blob);
    } else if (form.elements.quitar_foto.checked) {
      await fotoAnimalBorrar(foto);
      foto = '';
    }

    const datos = {
      name: clean(f.name), tag, foto,
      id_raza: f.raza || '', sexo: clean(f.sexo), estado: clean(f.estado),
      id_potrero: f.potrero || '', birth: f.birth || '', marca: clean(f.marca),
      chip: clean(f.chip), color: clean(f.color), hierro: clean(f.hierro),
      lote: clean(f.lote), situacion: clean(f.situacion), procedencia: clean(f.procedencia),
      padre: clean(f.padre), madre: clean(f.madre),
      ultimo_parto: f.ultimo_parto || '', ultimo_celo: f.ultimo_celo || '',
      fecha_prenez: f.fecha_prenez || '', parto_esperado: f.parto_esperado || '',
      reproductor: clean(f.reproductor), tipo_servicio: clean(f.tipo_servicio),
      servicios: numero(f.servicios), partos: numero(f.partos), abortos: numero(f.abortos),
      peso_kg: numero(f.peso_kg), peso_fecha: f.peso_fecha || '',
      condicion_corporal: numero(f.condicion_corporal),
      notas_salud: clean(f.notas_salud), observaciones: clean(f.observaciones)
    };
    if (idEditando) {
      const b = bovino(idEditando); if (b) Object.assign(b, datos);
    } else {
      db.bovinos.unshift(Object.assign({ id_bovino: idBov }, datos));
    }
    idEditando = null;
    save(); form.reset(); document.getElementById('modalBovino').close(); renderAll();
  } catch (err) {
    alert('No se pudo guardar la foto: ' + err.message);
  } finally {
    guardandoBovino = false;
    if (boton) { boton.disabled = false; boton.textContent = textoBoton; }
  }
});

$('#formTratamiento').addEventListener('submit', e => {
  e.preventDefault();
  const f = Object.fromEntries(new FormData(e.target));
  if (!f.bovino || !bovino(f.bovino)) { alert('Selecciona un animal válido.'); return; }
  if (!medicamento(f.medicamento)) { alert('Selecciona un medicamento válido.'); return; }
  db.tratamientos.unshift({ id_tratamiento: uid('trat'), id_bovino: f.bovino, id_medicamento: f.medicamento, tipo_procedimiento: f.tipo, fecha_tratamiento: f.fecha, dosis_ml: Number(f.dosis), nota: clean(f.nota) });
  save(); e.target.reset(); document.getElementById('modalTratamiento').close(); renderAll();
});

$('#formMedicamento').addEventListener('submit', e => {
  e.preventDefault();
  const f = Object.fromEntries(new FormData(e.target));
  db.medicamentos.push({ id_medicamento: uid('med'), nombre_farmaco: clean(f.nombre), dias_retiro_ica: Number(f.retiro) });
  save(); e.target.reset(); document.getElementById('modalMedicamento').close(); renderAll();
});

$('#formEvento').addEventListener('submit', e => {
  e.preventDefault();
  const f = Object.fromEntries(new FormData(e.target));
  const abiertos = ['Inseminación', 'Monta Natural'].includes(f.tipo) ? diasDesde(f.fecha) : null;
  db.eventos.unshift({ id_evento: uid('ev'), id_bovino: f.bovino, tipo_evento: f.tipo, fecha_evento: f.fecha, dias_abiertos_calc: abiertos, nota: clean(f.nota) });
  if (f.tipo === 'Parto') { const b = bovino(f.bovino); if (b && b.sexo === 'Hembra') b.estado = 'En Ordeño'; }
  save(); e.target.reset(); document.getElementById('modalEvento').close(); renderAll();
});

$('#formPesaje').addEventListener('submit', e => {
  e.preventDefault();
  const f = Object.fromEntries(new FormData(e.target));
  if (retiroPendiente(f.bovino) > 0 && !confirm('La vaca está en retiro de leche. ¿Registrar el pesaje de todos modos?')) return;
  db.pesajes.unshift({ id_pesaje: uid('pes'), id_bovino: f.bovino, fecha_pesaje: f.fecha, hora_pesaje: f.hora, litros_obtenidos: Number(f.litros) });
  save(); e.target.reset(); document.getElementById('modalPesaje').close(); renderAll();
});

$('#formEntrega').addEventListener('submit', e => {
  e.preventDefault();
  const f = Object.fromEntries(new FormData(e.target));
  const enRetiro = db.bovinos.filter(b => retiroPendiente(b.id_bovino) > 0).length;
  let litros = Number(f.litros);
  if (enRetiro && litros > db.pesajes.filter(p => p.fecha_pesaje === f.fecha).reduce((s, p) => s + p.litros_obtenidos, 0) + 1) {
    if (!confirm('Hay ' + enRetiro + ' animal(es) en retiro de leche. Verifica que esa leche NO esté incluida. ¿Continuar?')) return;
  }
  db.entregas.unshift({ id_entrega: uid('ent'), fecha_entrega: f.fecha, litros_totales: litros, valor_bruto_est: Number(f.valor), recuento_ufc: Number(f.ufc) });
  save(); e.target.reset(); document.getElementById('modalEntrega').close(); renderAll();
});

$('#formMovimiento').addEventListener('submit', e => {
  e.preventDefault();
  const f = Object.fromEntries(new FormData(e.target));
  db.movimientos.unshift({ id_mov: uid('mov'), id_potrero: f.potrero, accion: f.accion === 'Entrada al potrero' ? 'Entrada' : 'Salida', fecha: f.fecha, cantidad: Number(f.cantidad) });
  const p = potrero(f.potrero);
  if (p) { p.estado = f.accion.startsWith('Entrada') ? 'Ocupado' : 'Descanso'; p.desde = f.fecha; }
  save(); e.target.reset(); document.getElementById('modalMovimiento').close(); renderAll();
});

$('#formPotrero').addEventListener('submit', e => {
  e.preventDefault();
  const f = Object.fromEntries(new FormData(e.target));
  db.potreros.push({ id_potrero: uid('pot'), nombre_potrero: clean(f.nombre), dias_ocupacion: Number(f.ocupacion), dias_descanso_prv: Number(f.descanso), estado: 'Libre', desde: null });
  save(); e.target.reset(); document.getElementById('modalPotrero').close(); renderAll();
});

/* ---------- Navegación ---------- */
$$('.nav-item').forEach(button => button.addEventListener('click', () => {
  $$('.nav-item').forEach(item => item.classList.remove('active')); button.classList.add('active');
  $$('.page').forEach(page => page.classList.remove('active-page')); document.querySelector('#' + button.dataset.page).classList.add('active-page');
  $('#pageTitle').textContent = button.dataset.page === 'inicio' ? 'Panel de control' : button.textContent.trim().replace(/\d+$/, '');
  window.scrollTo({ top: 0, behavior: 'smooth' });
}));
$$('[data-page-link]').forEach(btn => btn.addEventListener('click', () => document.querySelector('[data-page="' + btn.dataset.pageLink + '"]').click()));

/* ---------- Exportar CSV ---------- */
$('#exportCsv').addEventListener('click', () => {
  const rows = [['Nombre', 'Arete', 'Raza', 'Sexo', 'Estado', 'Situación', 'Potrero', 'Lote', 'Nacimiento', 'Marca', 'Chip', 'Padre', 'Madre', 'Peso kg', 'Último parto', 'Partos', 'Parto esperado', 'Reproductor', 'Retiro dias restantes']].concat(
    db.bovinos.map(b => [b.name, b.tag, raza(b.id_raza), b.sexo, b.estado, b.situacion || '', (potrero(b.id_potrero) || {}).nombre_potrero || '', b.lote || '', b.birth, b.marca || '', b.chip || '', b.padre || '', b.madre || '', b.peso_kg, b.ultimo_parto || '', b.partos, b.parto_esperado || '', b.reproductor || '', retiroPendiente(b.id_bovino)]));
  const blob = new Blob(['\ufeff' + rows.map(r => r.map(csvSeguro).join(',')).join('\r\n')], { type: 'text/csv;charset=utf-8;' });
  const link = Object.assign(document.createElement('a'), { href: URL.createObjectURL(blob), download: 'proganado-inventario.csv' });
  link.click(); setTimeout(() => URL.revokeObjectURL(link.href), 0);
});


/* ---------- Contabilidad: entradas y salidas con foto de la factura ---------- */
// Los movimientos van en db.contabilidad (localStorage). Las fotos van en IndexedDB,
// porque localStorage tiene un límite pequeño y las imágenes ocupan mucho espacio.
const FOTOS_DB = 'proGanadoFacturas';
let idbPromesa = null;
function idbAbrir() {
  if (!idbPromesa) idbPromesa = new Promise((res, rej) => {
    const req = indexedDB.open(FOTOS_DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore('facturas');
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
  return idbPromesa;
}
async function idbOp(modo, fn) {
  const bd = await idbAbrir();
  return new Promise((res, rej) => {
    const tx = bd.transaction('facturas', modo);
    const req = fn(tx.objectStore('facturas'));
    tx.oncomplete = () => res(req ? req.result : undefined);
    tx.onerror = () => rej(tx.error);
    tx.onabort = () => rej(tx.error);
  });
}
async function fotoGuardar(id, blob) {
  if (servidorOK) {
    const r = await fetch('/api/factura/' + id, { method: 'PUT', headers: { 'Content-Type': 'image/jpeg' }, body: blob });
    if (!r.ok) throw new Error('el servidor no guardó la foto (' + r.status + ')');
    return;
  }
  return idbOp('readwrite', s => s.put(blob, id));
}
async function fotoLeer(id) {
  if (servidorOK) {
    const r = await fetch('/api/factura/' + id, { cache: 'no-store' });
    if (r.ok) return r.blob();
  }
  return idbOp('readonly', s => s.get(id));
}
async function fotoBorrar(id) {
  if (servidorOK) await fetch('/api/factura/' + id, { method: 'DELETE' }).catch(() => {});
  return idbOp('readwrite', s => s.delete(id)).catch(() => {});
}

const leerComoDataURL = file => new Promise((res, rej) => {
  const r = new FileReader(); r.onload = () => res(r.result); r.onerror = rej; r.readAsDataURL(file);
});
// Reduce la imagen al lado máximo indicado y la guarda como JPEG: se ve bien y ocupa poco espacio.
async function comprimirImagen(file, maxLado = 1600, calidad = 0.82) {
  const dataUrl = await leerComoDataURL(file);
  const img = await new Promise((res, rej) => { const i = new Image(); i.onload = () => res(i); i.onerror = () => rej(new Error('imagen no válida')); i.src = dataUrl; });
  const escala = Math.min(1, maxLado / Math.max(img.naturalWidth, img.naturalHeight));
  const c = document.createElement('canvas');
  c.width = Math.max(1, Math.round(img.naturalWidth * escala));
  c.height = Math.max(1, Math.round(img.naturalHeight * escala));
  const ctx = c.getContext('2d');
  ctx.fillStyle = '#fff';
  ctx.fillRect(0, 0, c.width, c.height);
  ctx.drawImage(img, 0, 0, c.width, c.height);
  return new Promise((res, rej) => c.toBlob(b => b ? res(b) : rej(new Error('No se pudo procesar la imagen.')), 'image/jpeg', calidad));
}
function comprimirFactura(file) { return comprimirImagen(file, 1600, 0.82); }

const esAdminActual = () => esAdmin();
const pesos = n => '$ ' + Number(n || 0).toLocaleString('es-CO');
const fechaLarga = f => {
  const d = fechaValida(f);
  return d ? d.toLocaleDateString('es-CO', { day: 'numeric', month: 'short', year: 'numeric' }) : '—';
};

function renderContab() {
  const todos = db.contabilidad || [];
  const ing = todos.filter(c => c.tipo === 'Entrada').reduce((s, c) => s + c.valor, 0);
  const egr = todos.filter(c => c.tipo === 'Salida').reduce((s, c) => s + c.valor, 0);
  $('#cIng').textContent = pesos(ing);
  const nReg = n => n + (n === 1 ? ' registro' : ' registros');
  $('#cIngN').textContent = nReg(todos.filter(c => c.tipo === 'Entrada').length);
  $('#cEgr').textContent = pesos(egr);
  $('#cEgrN').textContent = nReg(todos.filter(c => c.tipo === 'Salida').length);
  $('#cSaldo').textContent = pesos(ing - egr);
  $('#cSinFoto').textContent = todos.filter(c => !c.fotoId).length;

  const bus = clean($('#cBuscar').value).toLowerCase(), tipo = $('#cTipo').value, mes = $('#cMes').value;
  const lista = todos
    .filter(c => (tipo === 'Todos' || c.tipo === tipo) && (!mes || c.fecha.startsWith(mes)) &&
      [c.concepto, c.tercero, c.numero, c.categoria].join(' ').toLowerCase().includes(bus))
    .sort((a, b) => b.fecha.localeCompare(a.fecha));

  const tb = $('#cBody'); tb.replaceChildren();
  const celda = (texto, cls) => { const td = document.createElement('td'); if (cls) td.className = cls; td.textContent = texto; return td; };
  const boton = (texto, cls, onClick) => { const b = document.createElement('button'); b.className = 'mini-btn ' + (cls || ''); b.textContent = texto; b.addEventListener('click', onClick); return b; };

  for (const c of lista) {
    const tr = document.createElement('tr');
    const badge = document.createElement('span');
    badge.className = 'badge ' + (c.tipo === 'Entrada' ? 'b-blue' : 'b-red'); badge.textContent = c.tipo;
    const tdTipo = document.createElement('td'); tdTipo.append(badge);
    const tdFoto = document.createElement('td'); tdFoto.style.whiteSpace = 'nowrap';
    if (c.fotoId) tdFoto.append(boton('Ver factura', '', () => verFactura(c.fotoId)));
    else { const sf = document.createElement('span'); sf.className = 'badge b-amber'; sf.textContent = 'Sin foto'; tdFoto.append(sf, document.createTextNode(' '), boton('Adjuntar', '', () => adjuntarFactura(c.id))); }
    const tdAcc = document.createElement('td');
    if (esAdminActual()) tdAcc.append(boton('🗑', 'danger', () => eliminarMovimiento(c.id)));
    const signo = c.tipo === 'Entrada' ? '+ ' : '− ';
    tr.append(celda(fechaLarga(c.fecha)), tdTipo, celda(c.concepto), celda(c.tercero), celda(c.numero || '—'),
      celda(c.categoria), celda(c.metodo), celda(signo + pesos(c.valor), 'num ' + (c.tipo === 'Entrada' ? 'pos' : 'neg')), tdFoto, tdAcc);
    tb.append(tr);
  }
  $('#cVacio').style.display = lista.length ? 'none' : 'block';
  $('#cVacio').textContent = todos.length ? 'Ningún movimiento coincide con los filtros.' : 'Aún no hay movimientos. Registra la primera entrada o salida de dinero.';
}

function adjuntarFactura(id) {
  const input = document.createElement('input');
  input.type = 'file'; input.accept = 'image/*';
  input.addEventListener('change', async () => {
    const archivo = input.files[0]; if (!archivo) return;
    try {
      const blob = await comprimirFactura(archivo);
      await fotoGuardar(id, blob);
      const reg = db.contabilidad.find(c => c.id === id); if (reg) reg.fotoId = id;
      save(); renderAll();
    } catch (err) { alert('No se pudo adjuntar la foto: ' + err.message); }
  });
  input.click();
}

async function verFactura(fotoId) {
  try {
    const blob = await fotoLeer(fotoId);
    if (!blob) return alert('No se encontró la foto de esta factura en este equipo.');
    const url = URL.createObjectURL(blob);
    window.open(url, '_blank');
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  } catch (err) { alert('No se pudo abrir la factura: ' + err.message); }
}

async function eliminarMovimiento(id) {
  if (!esAdminActual()) return alert('Solo el administrador puede eliminar movimientos.');
  if (!confirm('¿Eliminar este movimiento y su factura adjunta?')) return;
  const reg = db.contabilidad.find(c => c.id === id);
  if (reg && reg.fotoId) { try { await fotoBorrar(reg.fotoId); } catch (e) { /* si falla, el movimiento igual se elimina */ } }
  db.contabilidad = db.contabilidad.filter(c => c.id !== id);
  save(); renderAll();
}

$('#formContab').addEventListener('submit', async e => {
  e.preventDefault();
  const form = e.target;
  const f = Object.fromEntries(new FormData(form));
  const valor = Math.round(Number(f.valor));
  if (!(valor > 0)) return alert('El valor debe ser mayor que cero.');
  const archivo = form.elements.foto.files[0];
  if (archivo && !archivo.type.startsWith('image/')) return alert('Solo se aceptan imágenes (JPG, PNG o WEBP).');
  if (archivo && archivo.size > 15 * 1024 * 1024) return alert('La foto supera 15 MB. Usa una imagen más pequeña.');
  const id = uid('cnt');
  const reg = { id, tipo: f.tipo, fecha: f.fecha, concepto: clean(f.concepto), tercero: clean(f.tercero), numero: clean(f.numero),
    categoria: f.categoria, metodo: f.metodo, valor, notas: clean(f.notas), fotoId: null, creado: hoy() };
  try {
    if (archivo) { await fotoGuardar(id, await comprimirFactura(archivo)); reg.fotoId = id; }
  } catch (err) { return alert('No se pudo guardar la foto: ' + err.message); }
  db.contabilidad = db.contabilidad || [];
  db.contabilidad.unshift(reg);
  save(); form.reset(); document.getElementById('modalContab').close(); renderAll();
});

$('#cBuscar').addEventListener('input', renderContab);
$('#cTipo').addEventListener('change', renderContab);
$('#cMes').addEventListener('change', renderContab);

$('#contabExport').addEventListener('click', () => {
  const rows = [['Fecha', 'Tipo', 'Concepto', 'Tercero', 'Número de factura', 'Categoría', 'Método', 'Valor COP', 'Foto adjunta', 'Notas']]
    .concat((db.contabilidad || []).slice().sort((a, b) => a.fecha.localeCompare(b.fecha))
      .map(c => [c.fecha, c.tipo, c.concepto, c.tercero, c.numero, c.categoria, c.metodo, c.valor, c.fotoId ? 'Sí' : 'No', c.notas]));
  const blob = new Blob(['\ufeff' + rows.map(r => r.map(csvSeguro).join(',')).join('\r\n')], { type: 'text/csv;charset=utf-8;' });
  const link = Object.assign(document.createElement('a'), { href: URL.createObjectURL(blob), download: 'proganado-contabilidad.csv' });
  link.click(); setTimeout(() => URL.revokeObjectURL(link.href), 0);
});


/* ---------- Reporte mensual en PDF (se genera en el navegador, sin librerías) ---------- */
// Escribe un PDF sencillo: texto con Helvetica, tablas con líneas y fotos JPEG del anexo.
const pdfTexto = s => {
  // Helvetica (WinAnsi) solo tiene caracteres latinos: el resto se cambia por un símbolo parecido
  const limpio = String(s == null ? '' : s).replace(/[−–—]/g, '-').replace(/[“”]/g, '"').replace(/[‘’]/g, "'").replace(/…/g, '...');
  return limpio.replace(/[^\x00-\xff]/g, '?');
};
const pdfEscapar = s => pdfTexto(s).replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
const pdfBytes = str => { const u = new Uint8Array(str.length); for (let i = 0; i < str.length; i++) u[i] = str.charCodeAt(i) & 255; return u; };

function jpegTamano(bytes) {
  // Lee ancho y alto del marcador SOF del JPEG
  let i = 2;
  while (i < bytes.length - 9) {
    if (bytes[i] !== 0xFF) { i++; continue; }
    const m = bytes[i + 1];
    if (m === 0xD8 || m === 0x01 || (m >= 0xD0 && m <= 0xD7) || m === 0xFF) { i += (m === 0xFF ? 1 : 2); continue; }
    const len = (bytes[i + 2] << 8) | bytes[i + 3];
    if (m >= 0xC0 && m <= 0xC3) return { h: (bytes[i + 5] << 8) | bytes[i + 6], w: (bytes[i + 7] << 8) | bytes[i + 8] };
    i += 2 + len;
  }
  return null;
}

function construirPDF(paginas, imagenes) {
  // paginas: [{ contenido, imgs: [{ nombre, id }] }] · imagenes: [{ id, bytes, w, h }]
  const W = 595, H = 842;
  const objs = [];   // objs[n] = { cuerpo } (texto) o { bin, dict } (imagen JPEG)
  objs[1] = { cuerpo: '<< /Type /Catalog /Pages 2 0 R >>' };
  objs[3] = { cuerpo: '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>' };
  objs[4] = { cuerpo: '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>' };
  let siguiente = 5;
  // 1) número de objeto para cada imagen (después de las páginas)
  const numPagina = [];
  for (const p of paginas) { numPagina.push({ contenido: siguiente++, pagina: siguiente++ }); }
  const numImg = {};
  for (const im of imagenes) numImg[im.id] = siguiente++;
  // 2) páginas, contenidos y diccionarios de recursos
  const kids = [];
  paginas.forEach((p, i) => {
    const { contenido, pagina } = numPagina[i];
    const xo = p.imgs.map(im => '/' + im.nombre + ' ' + numImg[im.id] + ' 0 R').join(' ');
    objs[contenido] = { cuerpo: '<< /Length ' + p.contenido.length + ' >>\nstream\n' + p.contenido + '\nendstream' };
    objs[pagina] = { cuerpo: '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ' + W + ' ' + H + '] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> /XObject << ' + xo + ' >> >> /Contents ' + contenido + ' 0 R >>' };
    kids.push(pagina + ' 0 R');
  });
  objs[2] = { cuerpo: '<< /Type /Pages /Kids [' + kids.join(' ') + '] /Count ' + kids.length + ' >>' };
  for (const im of imagenes) objs[numImg[im.id]] = { bin: im.bytes, dict: '<< /Type /XObject /Subtype /Image /Width ' + im.w + ' /Height ' + im.h + ' /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ' + im.bytes.length + ' >>' };

  // 3) escribir el archivo con tabla de referencias (xref)
  const partes = []; let pos = 0; const offsets = [];
  const add = u => { partes.push(u); pos += u.length; };
  add(pdfBytes('%PDF-1.4\n%\xE2\xE3\xCF\xD3\n'));
  const total = siguiente - 1;
  for (let n = 1; n <= total; n++) {
    offsets[n] = pos;
    const o = objs[n];
    add(pdfBytes(n + ' 0 obj\n'));
    if (!o) add(pdfBytes('null'));
    else if (o.bin) { add(pdfBytes(o.dict + '\nstream\n')); add(o.bin); add(pdfBytes('\nendstream')); }
    else add(pdfBytes(o.cuerpo));
    add(pdfBytes('\nendobj\n'));
  }
  const xref = pos;
  let t = 'xref\n0 ' + (total + 1) + '\n0000000000 65535 f \n';
  for (let n = 1; n <= total; n++) t += String(offsets[n] || 0).padStart(10, '0') + ' 00000 n \n';
  t += 'trailer\n<< /Size ' + (total + 1) + ' /Root 1 0 R >>\nstartxref\n' + xref + '\n%%EOF\n';
  add(pdfBytes(t));
  return new Blob(partes, { type: 'application/pdf' });
}

async function generarReportePDF(mes, empresa, conAnexo) {
  const movs = (db.contabilidad || []).filter(c => c.fecha.startsWith(mes)).sort((a, b) => a.fecha.localeCompare(b.fecha));
  const ing = movs.filter(c => c.tipo === 'Entrada').reduce((s, c) => s + c.valor, 0);
  const egr = movs.filter(c => c.tipo === 'Salida').reduce((s, c) => s + c.valor, 0);
  const sinFoto = movs.filter(c => !c.fotoId).length;
  const [anio, mm] = mes.split('-');
  const nombreMes = new Date(Number(anio), Number(mm) - 1, 1).toLocaleDateString('es-CO', { month: 'long', year: 'numeric' });
  const money = n => (n < 0 ? '-$ ' : '$ ') + Math.abs(Math.round(n)).toLocaleString('es-CO');
  const fecha = f => f.split('-').reverse().join('/');
  const hoyTxt = new Date().toLocaleDateString('es-CO');
  const cortar = (txt, max) => { const s = pdfTexto(txt); return s.length > max ? s.slice(0, Math.max(0, max - 2)) + '..' : s; };

  const paginas = []; let p = null, y = 0;
  const M = 40, W = 595, H = 842, ancho = W - 2 * M;
  const rect = (x, yy, w, h, rgb) => rgb ? rgb.join(' ') + ' rg ' + x + ' ' + yy + ' ' + w + ' ' + h + ' re f\n' : '';
  const linea = (x1, y1, x2, y2) => '0.78 0.84 0.9 RG 0.5 w ' + x1 + ' ' + y1 + ' m ' + x2 + ' ' + y2 + ' l S\n';
  const texto = (x, yy, size, s, bold, rgb) => (rgb ? rgb.join(' ') + ' rg ' : '0.12 0.16 0.2 rg ') + 'BT /' + (bold ? 'F2' : 'F1') + ' ' + size + ' Tf ' + x + ' ' + yy + ' Td (' + pdfEscapar(s) + ') Tj ET\n';
  const nuevaPagina = () => { p = { contenido: '', imgs: [] }; paginas.push(p); y = H - M; };

  // Portada / encabezado del reporte
  nuevaPagina();
  p.contenido += rect(0, H - 92, W, 92, [0.176, 0.243, 0.314]);
  p.contenido += texto(M, H - 42, 18, 'Reporte contable mensual', true, [1, 1, 1]);
  p.contenido += texto(M, H - 62, 10, cortar(empresa || 'ProGanado', 90) + '  ·  ' + nombreMes, false, [0.88, 0.91, 0.94]);
  p.contenido += texto(M, H - 78, 8, 'Generado con ProGanado el ' + hoyTxt, false, [0.75, 0.8, 0.85]);
  y = H - 92 - 28;
  const tarjetas = [['Entradas', money(ing)], ['Salidas', money(egr)], ['Saldo del mes', money(ing - egr)], ['Movimientos sin factura', String(sinFoto)]];
  const tw = (ancho - 30) / 4;
  tarjetas.forEach(([lab, val], i) => {
    const x = M + i * (tw + 10);
    p.contenido += rect(x, y - 46, tw, 52, [0.965, 0.976, 0.984]);
    p.contenido += texto(x + 10, y - 16, 8, lab, false, [0.4, 0.46, 0.52]);
    p.contenido += texto(x + 10, y - 36, 13, val, true);
  });
  y -= 72;

  // Tabla de movimientos
  const cols = [['Fecha', 54], ['Tipo', 46], ['Concepto', 124], ['Tercero', 88], ['Factura', 60], ['Categoría', 85], ['Valor', 58]];
  const encabezado = () => {
    p.contenido += texto(M, y, 12, 'Movimientos del mes', true);
    y -= 16;
    p.contenido += rect(M, y - 4, ancho, 16, [0.89, 0.93, 0.95]);
    let x = M + 4;
    for (const [nom, w] of cols) { p.contenido += texto(x, y + 1, 7.5, nom.toUpperCase(), true, [0.24, 0.33, 0.42]); x += w; }
    y -= 16;
  };
  const filaTabla = (vals, bold) => {
    let x = M + 4;
    vals.forEach((v, i) => {
      const w = cols[i][1];
      const max = Math.floor((w - 8) / 4.1);
      p.contenido += texto(x, y, 7.5, cortar(v, max), bold);
      x += w;
    });
    p.contenido += linea(M, y - 4, M + ancho, y - 4);
    y -= 15;
  };
  const asegurar = () => { if (y < 110) { nuevaPagina(); encabezado(); } };

  encabezado();
  if (!movs.length) { p.contenido += texto(M + 4, y, 9, 'No hay movimientos registrados en este mes.', false); y -= 18; }
  for (const c of movs) {
    asegurar();
    filaTabla([fecha(c.fecha), c.tipo, c.concepto, c.tercero, c.numero || '-', c.categoria, (c.tipo === 'Salida' ? '-' : '+') + ' ' + money(c.valor)], false);
  }

  // Resumen por categoría
  y -= 10; asegurar();
  p.contenido += texto(M, y, 12, 'Resumen por categoría', true); y -= 16;
  p.contenido += rect(M, y - 4, ancho, 16, [0.89, 0.93, 0.95]);
  const colsCat = [['Categoría', 200], ['Entradas', 110], ['Salidas', 110], ['Neto', 95]];
  let xc = M + 4; for (const [nom, w] of colsCat) { p.contenido += texto(xc, y + 1, 7.5, nom.toUpperCase(), true, [0.24, 0.33, 0.42]); xc += w; }
  y -= 16;
  const categorias = [...new Set(movs.map(c => c.categoria))].sort();
  for (const cat of categorias) {
    asegurar();
    const e = movs.filter(c => c.categoria === cat && c.tipo === 'Entrada').reduce((s, c) => s + c.valor, 0);
    const sa = movs.filter(c => c.categoria === cat && c.tipo === 'Salida').reduce((s, c) => s + c.valor, 0);
    let xx = M + 4;
    [cat, money(e), money(sa), money(e - sa)].forEach((v, i) => { p.contenido += texto(xx, y, 8, cortar(v, Math.floor((colsCat[i][1] - 8) / 4.3)), i === 0 ? false : false); xx += colsCat[i][1]; });
    p.contenido += linea(M, y - 4, M + ancho, y - 4);
    y -= 15;
  }
  asegurar();
  p.contenido += rect(M, y - 6, ancho, 18, [0.176, 0.243, 0.314]);
  p.contenido += texto(M + 6, y, 9, 'TOTAL DEL MES', true, [1, 1, 1]);
  p.contenido += texto(M + 4 + 200, y, 9, money(ing), true, [1, 1, 1]);
  p.contenido += texto(M + 4 + 310, y, 9, money(egr), true, [1, 1, 1]);
  p.contenido += texto(M + 4 + 420, y, 9, money(ing - egr), true, [0.88, 0.67, 0.29]);
  y -= 28;

  // Anexo: fotos de las facturas
  const conFoto = movs.filter(c => c.fotoId);
  if (conAnexo && conFoto.length) {
    const imagenes = [];
    let num = 1;
    for (const c of conFoto) {
      nuevaPagina();
      p.contenido += rect(0, H - 60, W, 60, [0.176, 0.243, 0.314]);
      p.contenido += texto(M, H - 30, 13, 'Anexo · Factura ' + (c.numero || '(sin número)'), true, [1, 1, 1]);
      p.contenido += texto(M, H - 46, 9, fecha(c.fecha) + '  ·  ' + c.tipo + '  ·  ' + cortar(c.concepto, 70) + '  ·  ' + money(c.valor), false, [0.88, 0.91, 0.94]);
      let blob = null;
      try { blob = await fotoLeer(c.fotoId); } catch (e) { blob = null; }
      if (!blob) { p.contenido += texto(M, H - 100, 10, 'La foto de esta factura no se encontró en el equipo.', false); continue; }
      const bytes = new Uint8Array(await blob.arrayBuffer());
      const tam = jpegTamano(bytes);
      if (!tam) { p.contenido += texto(M, H - 100, 10, 'La foto no es un JPEG válido.', false); continue; }
      const escala = Math.min((ancho) / tam.w, (H - 140) / tam.h, 1.6);
      const dw = tam.w * escala, dh = tam.h * escala;
      const nombre = 'Im' + num; const id = 'img' + num++;
      imagenes.push({ id, bytes, w: tam.w, h: tam.h });
      p.imgs.push({ nombre, id });
      p.contenido += 'q ' + dw.toFixed(2) + ' 0 0 ' + dh.toFixed(2) + ' ' + (M + (ancho - dw) / 2).toFixed(2) + ' ' + (H - 80 - dh).toFixed(2) + ' cm /' + nombre + ' Do Q\n';
    }
    return construirPDFConImagenes(paginas, imagenes);
  }
  return construirPDFConImagenes(paginas, []);
}

function construirPDFConImagenes(paginas, imagenes) {
  // Pie de página con número de página, añadido al final de cada página
  const total = paginas.length;
  paginas.forEach((pg, i) => {
    pg.contenido += '0.45 0.5 0.56 rg BT /F1 7.5 Tf 40 22 Td (' + pdfEscapar('Generado con ProGanado  ·  Página ' + (i + 1) + ' de ' + total) + ') Tj ET\n';
  });
  return construirPDF(paginas, imagenes);
}

$('#formReporte').addEventListener('submit', async e => {
  e.preventDefault();
  const form = e.target;
  const f = Object.fromEntries(new FormData(form));
  if (!f.mes) return alert('Elige el mes del reporte.');
  const boton = form.querySelector('button[value=default]');
  boton.disabled = true; boton.textContent = 'Generando…';
  try {
    const blob = await generarReportePDF(f.mes, clean(f.empresa), !!form.elements.anexo.checked);
    const url = URL.createObjectURL(blob);
    const link = Object.assign(document.createElement('a'), { href: url, download: 'reporte-contable-' + f.mes + '.pdf' });
    link.click(); setTimeout(() => URL.revokeObjectURL(url), 2000);
    document.getElementById('modalReporte').close();
  } catch (err) { alert('No se pudo generar el PDF: ' + err.message); }
  finally { boton.disabled = false; boton.textContent = 'Generar PDF'; }
});

/* ---------- Arranque ---------- */
function renderAll() {
  fillSelects();
  renderGanado(); renderCartilla(); renderSalud(); renderRepro(); renderProduccion(); renderPotreros(); renderMovs(); renderInicio(); renderContab();
}
$('#searchAnimals').addEventListener('input', renderGanado);
$('#categoryFilter').addEventListener('change', renderGanado);
$('#cartillaSelect').addEventListener('change', renderCartilla);
$('#today').textContent = new Intl.DateTimeFormat('es-CO', { weekday: 'long', day: 'numeric', month: 'long' }).format(new Date());
// Renderiza los datos al cargar; la autenticación controla qué se muestra.
renderAll();
sincronizarConServidor();
