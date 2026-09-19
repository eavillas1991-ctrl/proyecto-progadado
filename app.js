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
const fmtFecha = f => new Date(f + 'T12:00:00').toLocaleDateString('es-CO', { day: 'numeric', month: 'short' });
const mesCorto = f => new Date(f + 'T12:00:00').toLocaleDateString('es-CO', { month: 'short' }).replace('.', '').slice(0, 3).toUpperCase();
const clean = v => String(v == null ? '' : v).trim();
const uid = p => p + '_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);

/* ---------- Datos semilla (coherentes con el MR) ---------- */
const TODOS_ARETES = '452,458,627,629,635,972,1047,1069,1074,1075,1078,1095,1106,1151,1153,1162,1164,1172,1201,1225,1226,1227,1233,1234,1236,1237,1239,1249,1253,1261,1293,1297,1311,1317,1320,1322,1324,1327,1330,1331,1332,1342,1343,1348,1349,1353,1355,1363,1366,1369,1377,1379,1381,1386,1387,1388,1389,1391,1393,1399,1400,1403,1408,1410,1413,1418,1420,1421,1422,1428,1430,1431,1436,1441,1466,1467,1469,1478,1479,1483,1485,1488,1492,1493,1496,1497,1507,1511,1513,1516,1519,1520,1522,1527,1534,1537,1559,1563,1566,1575,1580,1587,1589,1592,1593,1598,1599,1601,1603,1604,1606,1609,1610,1611,1612,1844'.split(',');

/* Completa el hato con TODAS las vacas fotografiadas del ZIP (arete real + foto) */
function completarHato(lista, razasRot, potesRot) {
  const yaEstan = new Set(lista.map(b => b.tag));
  for (const tag of TODOS_ARETES) {
    if (yaEstan.has(tag)) continue;
    const n = parseInt(tag, 10);
    const año = 2019 + (n % 8);
    const mes = String(1 + (n % 12)).padStart(2, '0');
    const dia = String(1 + (n % 28)).padStart(2, '0');
    let estado;
    if (año >= 2026) estado = 'Ternera';
    else if (año === 2025) estado = 'Novilla Vientre';
    else estado = n % 5 === 0 ? 'Horra Seca' : 'En Ordeño';
    lista.push({ id_bovino: 'bov_' + tag, name: 'Vaca ' + tag, tag: tag, id_raza: razasRot[n % razasRot.length], sexo: 'Hembra', estado: estado, id_potrero: potesRot[n % potesRot.length], birth: año + '-' + mes + '-' + dia, marca: 'Arete ICA ' + tag, foto: 'assets/ganado/vaca_' + tag + '.jpg' });
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
      // 12 vacas REALES del hato (fotos de assets/ganado/, aretes del registro de la finca)
      { id_bovino: 'bov_1074', name: 'Vaca 1074', tag: '1074', id_raza: razaGyr, sexo: 'Hembra', estado: 'En Ordeño', id_potrero: potNorte, birth: '2021-06-18', marca: 'Arete ICA 1074', foto: 'assets/ganado/vaca_1074.jpg' },
      { id_bovino: 'bov_1075', name: 'Vaca 1075', tag: '1075', id_raza: razaHolstein, sexo: 'Hembra', estado: 'En Ordeño', id_potrero: potNorte, birth: '2022-02-03', marca: 'Arete ICA 1075', foto: 'assets/ganado/vaca_1075.jpg' },
      { id_bovino: 'bov_1078', name: 'Vaca 1078', tag: '1078', id_raza: razaHolstein, sexo: 'Hembra', estado: 'En Ordeño', id_potrero: potSur, birth: '2020-11-24', marca: 'Arete ICA 1078', foto: 'assets/ganado/vaca_1078.jpg' },
      { id_bovino: 'bov_1095', name: 'Vaca 1095', tag: '1095', id_raza: razaSim, sexo: 'Hembra', estado: 'En Ordeño', id_potrero: potSur, birth: '2020-03-15', marca: 'Arete ICA 1095', foto: 'assets/ganado/vaca_1095.jpg' },
      { id_bovino: 'bov_1106', name: 'Vaca 1106', tag: '1106', id_raza: razaGyr, sexo: 'Hembra', estado: 'En Ordeño', id_potrero: potNorte, birth: '2022-07-28', marca: 'Arete ICA 1106', foto: 'assets/ganado/vaca_1106.jpg' },
      { id_bovino: 'bov_1151', name: 'Vaca 1151', tag: '1151', id_raza: razaBrahman, sexo: 'Hembra', estado: 'Horra Seca', id_potrero: potEste, birth: '2020-10-02', marca: 'Arete ICA 1151', foto: 'assets/ganado/vaca_1151.jpg' },
      { id_bovino: 'bov_1153', name: 'Vaca 1153', tag: '1153', id_raza: razaHolstein, sexo: 'Hembra', estado: 'En Ordeño', id_potrero: potSur, birth: '2023-01-12', marca: 'Arete ICA 1153', foto: 'assets/ganado/vaca_1153.jpg' },
      { id_bovino: 'bov_1162', name: 'Vaca 1162', tag: '1162', id_raza: razaGyr, sexo: 'Hembra', estado: 'Novilla Vientre', id_potrero: potEste, birth: '2024-09-14', marca: 'Arete ICA 1162', foto: 'assets/ganado/vaca_1162.jpg' },
      { id_bovino: 'bov_1164', name: 'Vaca 1164', tag: '1164', id_raza: razaHolstein, sexo: 'Hembra', estado: 'En Ordeño', id_potrero: potNorte, birth: '2021-11-08', marca: 'Arete ICA 1164', foto: 'assets/ganado/vaca_1164.jpg' },
      { id_bovino: 'bov_1172', name: 'Vaca 1172', tag: '1172', id_raza: razaSim, sexo: 'Hembra', estado: 'En Ordeño', id_potrero: potSur, birth: '2022-05-21', marca: 'Arete ICA 1172', foto: 'assets/ganado/vaca_1172.jpg' },
      { id_bovino: 'bov_635', name: 'Vaca 635', tag: '635', id_raza: razaBrahman, sexo: 'Macho', estado: 'Toro', id_potrero: potEste, birth: '2019-05-11', marca: 'Arete SINIGAN 635', foto: 'assets/ganado/vaca_635.jpg' },
      { id_bovino: 'bov_1201', name: 'Vaca 1201', tag: '1201', id_raza: razaGyr, sexo: 'Hembra', estado: 'Ternera', id_potrero: potNorte, birth: '2026-04-19', marca: 'Arete ICA 1201', foto: 'assets/ganado/vaca_1201.jpg' }
    ]; return completarHato(l, [razaGyr, razaHolstein, razaBrahman, razaSim], [potNorte, potSur, potEste]); })(),
    medicamentos: [
      { id_medicamento: medAftosa, nombre_farmaco: 'Vacuna Aftosa', dias_retiro_ica: 0 },
      { id_medicamento: medOxi, nombre_farmaco: 'Oxitetraciclina LA', dias_retiro_ica: 6 },
      { id_medicamento: medDesp, nombre_farmaco: 'Ivermectina 1%', dias_retiro_ica: 8 }
    ],
    tratamientos: [
      { id_tratamiento: 'trat_1', id_bovino: 'bov_1075', id_medicamento: medOxi, tipo_procedimiento: 'Tratamiento mastitis', fecha_tratamiento: diasAtras(1), dosis_ml: 15, nota: 'Cuarto trasero izquierdo' },
      { id_tratamiento: 'trat_2', id_bovino: 'bov_1201', id_medicamento: medDesp, tipo_procedimiento: 'Desparasitación', fecha_tratamiento: diasAtras(5), dosis_ml: 4, nota: '' },
      { id_tratamiento: 'trat_3', id_bovino: 'bov_1074', id_medicamento: medAftosa, tipo_procedimiento: 'Vacunación', fecha_tratamiento: diasAtras(40), dosis_ml: 2, nota: 'Ciclo anual' }
    ],
    eventos: [
      { id_evento: 'ev_1', id_bovino: 'bov_1074', tipo_evento: 'Parto', fecha_evento: '2026-04-19', dias_abiertos_calc: null, nota: 'Ternera de la 1074' },
      { id_evento: 'ev_2', id_bovino: 'bov_1106', tipo_evento: 'Inseminación', fecha_evento: diasAtras(80), dias_abiertos_calc: 80, nota: 'Semen Gyr' },
      { id_evento: 'ev_3', id_bovino: 'bov_1153', tipo_evento: 'Celo Observable', fecha_evento: diasAtras(6), dias_abiertos_calc: null, nota: '' },
      { id_evento: 'ev_4', id_bovino: 'bov_1075', tipo_evento: 'Inseminación', fecha_evento: diasAtras(30), dias_abiertos_calc: 30, nota: '' }
    ],
    pesajes: [
      { id_pesaje: 'pes_1', id_bovino: 'bov_1074', fecha_pesaje: hoy(), hora_pesaje: '06:10', litros_obtenidos: 13.2 },
      { id_pesaje: 'pes_2', id_bovino: 'bov_1078', fecha_pesaje: hoy(), hora_pesaje: '06:25', litros_obtenidos: 14.8 },
      { id_pesaje: 'pes_3', id_bovino: 'bov_1106', fecha_pesaje: hoy(), hora_pesaje: '06:40', litros_obtenidos: 11.5 },
      { id_pesaje: 'pes_4', id_bovino: 'bov_1153', fecha_pesaje: diasAtras(1), hora_pesaje: '06:15', litros_obtenidos: 12.4 },
      { id_pesaje: 'pes_5', id_bovino: 'bov_1075', fecha_pesaje: diasAtras(2), hora_pesaje: '06:20', litros_obtenidos: 10.9 }
    ],
    entregas: [
      { id_entrega: 'ent_1', fecha_entrega: diasAtras(2), litros_totales: 391, valor_bruto_est: 893000, recuento_ufc: 80000 }
    ],
    movimientos: [
      { id_mov: 'mov_1', id_potrero: potNorte, accion: 'Entrada', fecha: diasAtras(1), cantidad: 5 }
    ]
  };
}
function diasAtras(n) { const d = new Date(); d.setDate(d.getDate() - n); return d.toISOString().slice(0, 10); }

/* ---------- Persistencia ---------- */
let db = load();
function load() {
  try {
    const raw = localStorage.getItem(DB_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && parsed.bovinos) {
        // limpieza defensiva: registros huérfanos
        const ids = new Set(parsed.bovinos.map(b => b.id_bovino));
        parsed.tratamientos = (parsed.tratamientos || []).filter(t => ids.has(t.id_bovino));
        parsed.eventos = (parsed.eventos || []).filter(e => ids.has(e.id_bovino));
        parsed.pesajes = (parsed.pesajes || []).filter(p => ids.has(p.id_bovino));
        return parsed;
      }
    }
  } catch (e) { /* datos corruptos: regenerar */ }
  const fresh = seed();
  save(fresh);
  return fresh;
}
function save(data) { try { localStorage.setItem(DB_KEY, JSON.stringify(data || db)); } catch (e) { /* cuota llena */ } }

/* ---------- Helpers de dominio ---------- */
const raza = id => (db.razas.find(r => r.id_raza === id) || {}).nombre_raza || '—';
const potrero = id => db.potreros.find(p => p.id_potrero === id);
const bovino = id => db.bovinos.find(b => b.id_bovino === id);
const nombreBov = id => (bovino(id) || {}).name || '—';
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
  const meses = Math.floor((Date.now() - new Date(birth + 'T12:00:00')) / 2592000000);
  if (meses < 1) return '<1 mes';
  if (meses < 12) return meses + (meses === 1 ? ' mes' : ' meses');
  const años = Math.floor(meses / 12);
  return años + (años === 1 ? ' año' : ' años');
}

/* ---------- Render: Ganado + cartilla ---------- */
function renderGanado() {
  const q = clean($('#searchAnimals').value).toLowerCase();
  const filtro = $('#categoryFilter').value;
  const lista = db.bovinos.filter(b => (filtro === 'Todos' || b.estado === filtro) && (b.name + ' ' + b.tag).toLowerCase().includes(q));
  const tb = $('#animalsTable'); tb.replaceChildren();
  for (const b of lista) {
    const tr = document.createElement('tr');
    const retiro = retiroPendiente(b.id_bovino);
    const td1 = document.createElement('td');
    const avatar = b.foto ? '<img class="animal-foto" loading="lazy" title="Ver foto grande" src="' + b.foto + '" alt="' + b.name + '" />' : '<span class="animal-avatar">' + (b.sexo === 'Macho' ? '♂' : b.estado.includes('Tern') ? '◌' : '♀') + '</span>';
    td1.innerHTML = '<div class="animal-cell">' + avatar + '<strong>' + b.name + '</strong></div>';
    tr.append(td1);
    if (b.foto) { td1.querySelector('.animal-foto').addEventListener('click', () => abrirFoto(b.id_bovino)); }
    const celdas = [ '#' + b.tag, raza(b.id_raza), b.estado, (potrero(b.id_potrero) || {}).nombre_potrero || '—' ];
    for (const val of celdas) { const td = document.createElement('td'); td.textContent = val; tr.append(td); }
    const tdSeg = document.createElement('td');
    tdSeg.innerHTML = retiro > 0 ? '<span class="badge b-red">Retiro ' + retiro + ' d</span>' : '<span class="badge b-green">Al día</span>';
    const tdBtn = document.createElement('td');
    tdBtn.style.whiteSpace = 'nowrap';
    const btn = document.createElement('button'); btn.className = 'mini-btn'; btn.textContent = 'Cartilla';
    btn.addEventListener('click', () => { $('#cartillaSelect').value = b.id_bovino; renderCartilla(); $('#cartillaSelect').scrollIntoView({ behavior: 'smooth', block: 'center' }); });
    const btnEdit = document.createElement('button'); btnEdit.className = 'mini-btn'; btnEdit.textContent = '✎'; btnEdit.title = 'Editar animal';
    btnEdit.addEventListener('click', () => abrirEdicion(b.id_bovino));
    const btnDel = document.createElement('button'); btnDel.className = 'mini-btn danger'; btnDel.textContent = '🗑'; btnDel.title = 'Eliminar registro (solo administrador)';
    btnDel.addEventListener('click', () => eliminarBovino(b.id_bovino));
    tdBtn.append(btn, btnEdit);
    if (window.esAdmin && esAdmin()) tdBtn.append(btnDel); // eliminar: solo administradores
    tr.append(tdSeg, tdBtn); tb.append(tr);
  }
  $('#emptyState').style.display = lista.length ? 'none' : 'block';
  $('#herdCount').textContent = db.bovinos.length;
  $('#metricTotal').textContent = db.bovinos.length;
  const hembras = db.bovinos.filter(b => b.sexo === 'Hembra' && !b.estado.includes('Tern')).length;
  const machos = db.bovinos.filter(b => b.sexo === 'Macho').length;
  const crias = db.bovinos.filter(b => b.estado.includes('Tern')).length;
  $('#metricComp').textContent = hembras + ' hembras · ' + machos + ' machos · ' + crias + ' crías';

  // selector de cartilla
  const sel = $('#cartillaSelect');
  const previo = sel.value;
  sel.replaceChildren(...db.bovinos.map(b => new Option(b.name + ' · #' + b.tag, b.id_bovino)));
  if (previo && db.bovinos.some(b => b.id_bovino === previo)) sel.value = previo;
}

function renderCartilla() {
  const id = $('#cartillaSelect').value;
  const b = bovino(id);
  const cont = $('#cartillaContent');
  if (!b) { cont.replaceChildren(); return; }
  const tratamientos = db.tratamientos.filter(t => t.id_bovino === id).sort((a, c) => c.fecha_tratamiento.localeCompare(a.fecha_tratamiento));
  const eventos = db.eventos.filter(e => e.id_bovino === id).sort((a, c) => c.fecha_evento.localeCompare(a.fecha_evento));
  const pesajes = db.pesajes.filter(p => p.id_bovino === id).sort((a, c) => (c.fecha_pesaje + c.hora_pesaje).localeCompare(a.fecha_pesaje + a.hora_pesaje));
  const retiro = retiroPendiente(id);
  cont.innerHTML =
    '<div class="cartilla-head">' + (b.foto ? '<img src="' + b.foto + '" alt="' + b.name + '" />' : '') + '<div><strong>' + b.name + '</strong><span>' + (b.marca || 'Sin marca') + ' · ' + raza(b.id_raza) + '</span></div></div>' +
    '<div class="kpi-list">' +
    '<div><span>Raza</span><b>' + raza(b.id_raza) + '</b></div>' +
    '<div><span>Edad</span><b>' + edadTexto(b.birth) + '</b></div>' +
    '<div><span>Estado fisiológico</span><b>' + b.estado + '</b></div>' +
    '<div><span>Potrero</span><b>' + ((potrero(b.id_potrero) || {}).nombre_potrero || '—') + '</b></div>' +
    '<div><span>Identificación</span><b>' + (b.marca || 'Sin marca registrada') + '</b></div>' +
    '<div><span>Seguimiento médico</span><b>' + (retiro > 0 ? '<span class="badge b-red">LECHE SUSPENDIDA · retiro ' + retiro + ' días</span>' : '<span class="badge b-green">Sin retiro activo</span>') + '</b></div>' +
    '</div>' +
    '<p class="section-eyebrow eyebrow">Tratamientos y vacunas (' + tratamientos.length + ')</p>' +
    (tratamientos.length ? '<div class="reto-list">' + tratamientos.map(t => {
      const med = medicamento(t.id_medicamento) || {};
      const r = retiroDeTrat(t);
      return '<div class="reto"><span class="calendar">' + t.fecha_tratamiento.slice(8) + '<br><b>' + mesCorto(t.fecha_tratamiento) + '</b></span><div><strong>' + t.tipo_procedimiento + ' · ' + (med.nombre_farmaco || '?') + '</strong><p>Dosis ' + t.dosis_ml + ' ml' + (t.nota ? ' · ' + t.nota : '') + '</p></div><span class="spacer">' + (r > 0 ? '<span class="badge b-red">Leche suspendida ' + r + ' d</span>' : '<span class="badge b-green">Retiro cumplido</span>') + '</span></div>';
    }).join('') + '</div>' : '<p class="empty" style="display:block">Sin tratamientos registrados.</p>') +
    '<p class="section-eyebrow eyebrow">Eventos reproductivos (' + eventos.length + ')</p>' +
    (eventos.length ? '<div class="reto-list">' + eventos.map(e => '<div class="reto"><span class="calendar">' + e.fecha_evento.slice(8) + '<br><b>' + mesCorto(e.fecha_evento) + '</b></span><div><strong>' + e.tipo_evento + '</strong><p>' + (e.nota || '') + '</p></div><span class="spacer">' + (e.dias_abiertos_calc ? '<span class="badge b-amber">' + diasDesde(e.fecha_evento) + ' d abiertos</span>' : '') + '</span></div>').join('') + '</div>' : '<p class="empty" style="display:block">Sin eventos reproductivos.</p>') +
    '<p class="section-eyebrow eyebrow">Últimos pesajes (' + pesajes.length + ')</p>' +
    (pesajes.length ? '<div class="reto-list">' + pesajes.slice(0, 5).map(p => '<div class="reto"><span class="calendar">' + p.fecha_pesaje.slice(8) + '<br><b>' + mesCorto(p.fecha_pesaje) + '</b></span><div><strong>' + p.litros_obtenidos + ' L</strong><p>Ordeño de las ' + p.hora_pesaje + '</p></div></div>').join('') + '</div>' : '<p class="empty" style="display:block">Sin pesajes.</p>');
}
function retiroDeTrat(t) {
  const med = medicamento(t.id_medicamento);
  if (!med || !med.dias_retiro_ica) return 0;
  const fin = new Date(t.fecha_tratamiento + 'T12:00:00');
  fin.setDate(fin.getDate() + med.dias_retiro_ica);
  return Math.max(0, Math.ceil((fin - new Date()) / 86400000));
}
function diasDesde(f) { return Math.floor((Date.now() - new Date(f + 'T12:00:00')) / 86400000); }

/* ---------- Render: Salud ---------- */
function renderSalud() {
  const tb = $('#tratamientosTable'); tb.replaceChildren();
  const lista = [...db.tratamientos].sort((a, b) => b.fecha_tratamiento.localeCompare(a.fecha_tratamiento));
  let enRetiro = 0, activos = 0;
  for (const t of lista) {
    const med = medicamento(t.id_medicamento) || {};
    const r = retiroDeTrat(t);
    if (r > 0) { enRetiro++; activos++; }
    const tr = document.createElement('tr');
    tr.innerHTML = '<td><strong>' + nombreBov(t.id_bovino) + '</strong></td><td>' + t.tipo_procedimiento + '</td><td>' + (med.nombre_farmaco || '?') + '</td><td>' + fmtFecha(t.fecha_tratamiento) + '</td><td>' + t.dosis_ml + ' ml</td><td>' + (med.dias_retiro_ica || 0) + ' días</td><td>' + (r > 0 ? '<span class="badge b-red">Retiro ' + r + ' d</span>' : '<span class="badge b-green">Cumplido</span>') + '</td>';
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
    tr.innerHTML = '<td><strong>' + m.nombre_farmaco + '</strong></td><td>' + (m.dias_retiro_ica ? '<span class="badge b-amber">' + m.dias_retiro_ica + ' días</span>' : '<span class="badge b-green">Sin retiro</span>') + '</td>';
    mt.append(tr);
  }
}

/* ---------- Render: Reproducción ---------- */
function renderRepro() {
  const tb = $('#reproTable'); tb.replaceChildren();
  const lista = [...db.eventos].sort((a, b) => b.fecha_evento.localeCompare(a.fecha_evento));
  for (const e of lista.slice(0, 12)) {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td><strong>' + nombreBov(e.id_bovino) + '</strong></td><td>' + e.tipo_evento + '</td><td>' + fmtFecha(e.fecha_evento) + '</td><td>' + (e.dias_abiertos_calc ? diasDesde(e.fecha_evento) + ' d' : '—') + '</td><td>' + (e.nota || '') + '</td>';
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
  const partos = db.eventos.filter(e => e.tipo_evento === 'Parto' && e.fecha_evento.slice(0, 4) === String(new Date().getFullYear()));
  $('#reproPartos').textContent = partos.length;
  $('#reproPartosInfo').textContent = partos.length ? 'Último: ' + fmtFecha(partos.sort((a, b) => b.fecha_evento.localeCompare(a.fecha_evento))[0].fecha_evento) : '—';
}
function sumarDias(f, n) { const d = new Date(f + 'T12:00:00'); d.setDate(d.getDate() + n); return d.toISOString().slice(0, 10); }

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
  const pesajes = [...db.pesajes].sort((a, b) => (b.fecha_pesaje + b.hora_pesaje).localeCompare(a.fecha_pesaje + a.hora_pesaje)).slice(0, 10);
  for (const p of pesajes) {
    const tr = document.createElement('tr');
    const bloqueada = retiroPendiente(p.id_bovino) > 0;
    tr.innerHTML = '<td><strong>' + nombreBov(p.id_bovino) + '</strong>' + (bloqueada ? ' <span class="badge b-red">retiro</span>' : '') + '</td><td>' + fmtFecha(p.fecha_pesaje) + '</td><td>' + p.hora_pesaje + '</td><td>' + p.litros_obtenidos + ' L</td>';
    tp.append(tr);
  }
  $('#emptyPesajes').style.display = pesajes.length ? 'none' : 'block';

  const te = $('#entregasTable'); te.replaceChildren();
  const entregas = [...db.entregas].sort((a, b) => b.fecha_entrega.localeCompare(a.fecha_entrega)).slice(0, 10);
  for (const e of entregas) {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td>' + fmtFecha(e.fecha_entrega) + '</td><td>' + e.litros_totales + ' L</td><td>$ ' + Number(e.valor_bruto_est).toLocaleString('es-CO') + '</td><td>' + (e.recuento_ufc <= 100000 ? '<span class="badge b-green">' + e.recuento_ufc.toLocaleString('es-CO') + '</span>' : '<span class="badge b-amber">' + e.recuento_ufc.toLocaleString('es-CO') + '</span>') + '</td>';
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
    div.innerHTML = '<span class="calendar">▣</span><div><strong>' + p.nombre_potrero + '</strong><p>Ocupación ' + p.dias_ocupacion + ' d · descanso PRV ' + p.dias_descanso_prv + ' d' + (p.desde ? ' · desde ' + fmtFecha(p.desde) : '') + '</p></div><span class="spacer"><span class="badge ' + badge + '">' + p.estado + '</span></span>';
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
  $('#potrerosInfo').textContent = 'PRV ' + db.potreros.reduce((s, p) => s + p.dias_descanso_prv, 0) / (db.potreros.length || 1) + ' d descanso promedio';

  // sincronizar selects de potrero
  const opts = db.potreros.map(p => new Option(p.nombre_potrero, p.id_potrero));
  $('#potreroSelect').replaceChildren(new Option('Sin potrero', ''), ...opts);
  $('#movPotreroSelect').replaceChildren(...opts);
}

function renderMovs() {
  const tb = $('#movsTable'); tb.replaceChildren();
  const lista = [...db.movimientos].sort((a, b) => b.fecha.localeCompare(a.fecha)).slice(0, 12);
  for (const m of lista) {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td>' + fmtFecha(m.fecha) + '</td><td>' + m.cantidad + ' animales</td><td>' + ((potrero(m.id_potrero) || {}).nombre_potrero || '—') + '</td><td>' + (m.accion === 'Entrada' ? '<span class="badge b-blue">Entrada</span>' : '<span class="badge b-amber">Salida</span>') + '</td>';
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
    return '<div class="reminder"><span class="calendar' + (a.dias <= 0 ? ' urgent' : '') + '">' + dia.getDate() + '<br><b>' + dia.toLocaleDateString('es-CO', { month: 'short' }).slice(0, 3).toUpperCase() + '</b></span><div><strong>' + a.titulo + '</strong><p>' + a.sub + '</p></div>' + tag + '</div>';
  }).join('') || '<p class="empty" style="display:block">Sin eventos próximos.</p>';

  // Donut composición
  const hembras = db.bovinos.filter(b => b.sexo === 'Hembra' && !b.estado.includes('Tern')).length;
  const crias = db.bovinos.filter(b => b.estado.includes('Tern')).length;
  const machos = db.bovinos.filter(b => b.sexo === 'Macho').length;
  const total = db.bovinos.length || 1;
  const p1 = Math.round(hembras / total * 100), p2 = Math.round(crias / total * 100);
  $('#donut').style.background = 'conic-gradient(#50966f 0 ' + p1 + '%,#c8ae59 ' + p1 + '% ' + (p1 + p2) + '%,#9cb2c7 ' + (p1 + p2) + '% 100%)';
  $('#donutTotal').textContent = db.bovinos.length;
  $('#donutLegend').innerHTML = '<li><i class="female"></i> Hembras adultas <b>' + hembras + '</b></li><li><i class="calf"></i> Crías <b>' + crias + '</b></li><li><i class="male"></i> Machos <b>' + machos + '</b></li>';

  // Última entrega
  const ent = [...db.entregas].sort((a, b) => b.fecha_entrega.localeCompare(a.fecha_entrega))[0];
  $('#ultimaEntrega').innerHTML = ent ?
    '<div class="kpi-list"><div><span>Fecha</span><b>' + fmtFecha(ent.fecha_entrega) + '</b></div><div><span>Litros</span><b>' + ent.litros_totales + ' L</b></div><div><span>Valor bruto</span><b>$ ' + Number(ent.valor_bruto_est).toLocaleString('es-CO') + '</b></div><div><span>Calidad UFC</span><b>' + (ent.recuento_ufc <= 100000 ? '<span class="badge b-green">Apta Colanta</span>' : '<span class="badge b-amber">Revisar</span>') + '</b></div></div>'
    : '<p class="empty" style="display:block">Sin entregas registradas.</p>';

  // Actividad reciente
  const acts = [];
  for (const t of [...db.tratamientos].sort((a, b) => b.fecha_tratamiento.localeCompare(a.fecha_tratamiento)).slice(0, 2)) acts.push({ icon: '✚', t: t.tipo_procedimiento, s: nombreBov(t.id_bovino) + ' · ' + ((medicamento(t.id_medicamento) || {}).nombre_farmaco || ''), f: fmtFecha(t.fecha_tratamiento) });
  for (const p of [...db.pesajes].sort((a, b) => (b.fecha_pesaje + b.hora_pesaje).localeCompare(a.fecha_pesaje + a.hora_pesaje)).slice(0, 1)) acts.push({ icon: '◒', t: 'Pesaje de leche', s: nombreBov(p.id_bovino) + ' · ' + p.litros_obtenidos + ' L', f: fmtFecha(p.fecha_pesaje) });
  for (const m of [...db.movimientos].sort((a, b) => b.fecha.localeCompare(a.fecha)).slice(0, 1)) acts.push({ icon: '↔', t: 'Pastoreo · ' + m.accion, s: (potrero(m.id_potrero) || {}).nombre_potrero + ' · ' + m.cantidad + ' animales', f: fmtFecha(m.fecha) });
  $('#actividadReciente').innerHTML = acts.slice(0, 4).map(a => '<div class="activity-row"><span class="activity-icon">' + a.icon + '</span><div><strong>' + a.t + '</strong><p>' + a.s + '</p></div><time>' + a.f + '</time></div>').join('');
}

/* ---------- Selectores dependientes ---------- */
function fillSelects() {
  $('#razaSelect').replaceChildren(...db.razas.map(r => new Option(r.nombre_raza, r.id_raza)));
  const etiqueta = b => b.name + ' · #' + b.tag;
  $('#tratBovinoSelect').replaceChildren(...db.bovinos.map(b => new Option(etiqueta(b), b.id_bovino)));
  $('#evBovinoSelect').replaceChildren(...db.bovinos.map(b => new Option(etiqueta(b), b.id_bovino)));
  $('#pesBovinoSelect').replaceChildren(...db.bovinos.filter(b => b.estado === 'En Ordeño').map(b => new Option(etiqueta(b), b.id_bovino)));
  $('#tratMedSelect').replaceChildren(...db.medicamentos.map(m => new Option(m.nombre_farmaco + ' (retiro ' + m.dias_retiro_ica + ' d)', m.id_medicamento)));
  $('#cartillaSelect').replaceChildren(...db.bovinos.map(b => new Option(etiqueta(b), b.id_bovino)));
}

/* ---------- Lightbox de foto ---------- */
function abrirFoto(id) {
  const b = bovino(id); if (!b || !b.foto) return;
  $('#fotoGrande').src = b.foto;
  $('#fotoNombre').textContent = b.name;
  $('#fotoNombre').dataset.id = id;
  const r = retiroPendiente(id);
  $('#fotoDetalle').textContent = '#' + b.tag + ' · ' + raza(b.id_raza) + ' · ' + b.estado + (r > 0 ? ' · ⚠ retiro ' + r + ' d' : '');
  document.getElementById('fotoModal').showModal();
}
$('#fotoClose').addEventListener('click', () => document.getElementById('fotoModal').close());
$('#fotoCartilla').addEventListener('click', () => { const id = $('#fotoNombre').dataset.id; document.getElementById('fotoModal').close(); $('#cartillaSelect').value = id; renderCartilla(); $('#cartillaSelect').scrollIntoView({ behavior: 'smooth', block: 'center' }); });

/* ---------- Editar / eliminar animal ---------- */
let idEditando = null;
function abrirEdicion(id) {
  const b = bovino(id); if (!b) return;
  idEditando = id;
  fillSelects();
  $('#eyebrowBovino').textContent = 'Editar registro';
  $('#tituloBovino').textContent = 'Editar · ' + b.name;
  const f = $('#formBovino');
  f.name.value = b.name; f.tag.value = b.tag; f.raza.value = b.id_raza; f.sexo.value = b.sexo;
  f.estado.value = b.estado; f.potrero.value = b.id_potrero || ''; f.birth.value = b.birth; f.marca.value = b.marca || '';
  document.getElementById('modalBovino').showModal();
}
function eliminarBovino(id) {
  const b = bovino(id); if (!b) return;
  const relacionados = db.tratamientos.filter(t => t.id_bovino === id).length + db.eventos.filter(e => e.id_bovino === id).length + db.pesajes.filter(p => p.id_bovino === id).length;
  const msg = '¿Eliminar el registro de ' + b.name + ' (#' + b.tag + ')?' + (relacionados ? '\n\nTambién se borrarán ' + relacionados + ' registro(s) médicos y de producción asociados.' : '');
  if (!confirm(msg)) return;
  db.bovinos = db.bovinos.filter(x => x.id_bovino !== id);
  db.tratamientos = db.tratamientos.filter(t => t.id_bovino !== id);
  db.eventos = db.eventos.filter(e => e.id_bovino !== id);
  db.pesajes = db.pesajes.filter(p => p.id_bovino !== id);
  save(); renderAll();
}

/* ---------- Modales ---------- */
function openModal(id) {
  fillSelects();
  if (id === 'modalBovino') { idEditando = null; $('#eyebrowBovino').textContent = 'Nuevo registro'; $('#tituloBovino').textContent = 'Registrar animal'; $('#formBovino').reset(); }
  const d = document.getElementById(id); if (id === 'modalTratamiento') avisoTrat(); if (id === 'modalPesaje') avisoPesaje(); d.showModal();
}
$$('[data-open-modal]').forEach(btn => btn.addEventListener('click', () => openModal(btn.dataset.openModal)));

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
$('#formBovino').addEventListener('submit', e => {
  e.preventDefault();
  const f = Object.fromEntries(new FormData(e.target));
  if (db.bovinos.some(b => b.tag.toLowerCase() === clean(f.tag).toLowerCase() && b.id_bovino !== idEditando)) { alert('Ese número de arete ya existe.'); return; }
  const datos = { name: clean(f.name), tag: clean(f.tag), id_raza: f.raza, sexo: f.sexo, estado: f.estado, id_potrero: f.potrero || '', birth: f.birth, marca: clean(f.marca) };
  if (idEditando) {
    const b = bovino(idEditando); if (b) Object.assign(b, datos);
  } else {
    db.bovinos.unshift(Object.assign({ id_bovino: uid('bov') }, datos));
  }
  idEditando = null;
  save(); e.target.reset(); document.getElementById('modalBovino').close(); renderAll();
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
  const rows = [['Nombre', 'Arete', 'Raza', 'Sexo', 'Estado', 'Potrero', 'Nacimiento', 'Marca', 'Retiro dias restantes']].concat(
    db.bovinos.map(b => [b.name, b.tag, raza(b.id_raza), b.sexo, b.estado, (potrero(b.id_potrero) || {}).nombre_potrero || '', b.birth, b.marca || '', retiroPendiente(b.id_bovino)]));
  const blob = new Blob(['\ufeff' + rows.map(r => r.map(v => '"' + String(v).replaceAll('"', '""') + '"').join(',')).join('\r\n')], { type: 'text/csv;charset=utf-8;' });
  const link = Object.assign(document.createElement('a'), { href: URL.createObjectURL(blob), download: 'proganado-inventario.csv' });
  link.click(); setTimeout(() => URL.revokeObjectURL(link.href), 0);
});

/* ---------- Arranque ---------- */
function renderAll() {
  fillSelects();
  renderGanado(); renderCartilla(); renderSalud(); renderRepro(); renderProduccion(); renderPotreros(); renderMovs(); renderInicio();
}
$('#searchAnimals').addEventListener('input', renderGanado);
$('#categoryFilter').addEventListener('change', renderGanado);
$('#cartillaSelect').addEventListener('change', renderCartilla);
$('#today').textContent = new Intl.DateTimeFormat('es-CO', { weekday: 'long', day: 'numeric', month: 'long' }).format(new Date());
// El renderizado siempre corre al cargar (auth.js solo controla visibilidad;
// si la autenticación no está disponible, la app entra en modo abierto).
renderAll();
