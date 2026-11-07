# ProGanado · Gestión Ganadera

Aplicación web local para administrar un hato bovino: inventario, sanidad, reproducción, producción de leche, potreros PRV, contabilidad y usuarios.

Funciona en el equipo de la finca con un servidor Python que sirve la página y guarda los datos en SQLite. No requiere conexión a internet, salvo que se configure el envío de códigos 2FA por Gmail.

## Funcionalidades

- **Inventario**: ficha por animal, foto, raza, estado, potrero, edad y hoja de vida con el histórico médico, reproductivo y datos productivos. La hoja de vida permite actualizar identificación, genealogía, situación, fechas reproductivas, peso, condición corporal y notas, y agregar o reemplazar la foto del animal desde el mismo formulario.
- **Salud**: tratamientos, vacunas, medicamentos y control automático de los días de retiro ICA (leche suspendida).
- **Reproducción**: celos, inseminaciones, montas, partos y estimación de la fecha de parto.
- **Producción**: pesajes de leche, entregas a Colanta, calidad UFC y promedio por vaca.
- **Potreros PRV**: ocupación, descanso, rotación y movimientos de animales.
- **Contabilidad**: entradas y salidas, facturas con foto, filtros, exportación CSV y reporte mensual en PDF.
- **Usuarios**: roles administrador/usuario, límites de cuentas, cambio de contraseña y verificación en dos pasos (2FA) por correo.

## Requisitos

- Python 3.10 o superior (probado con Python 3.13).
- Un navegador moderno (Chrome, Edge o Firefox actualizados).
- Gmail con contraseña de aplicación solo si se desea enviar los códigos 2FA por correo.

## Inicio rápido

1. Abre `Iniciar ProGanado.bat` (Windows) o ejecuta:

   ```bat
   python servidor.py
   ```

2. Entra a <http://127.0.0.1:8899/index.html>.

3. En el primer uso, la pantalla de acceso pide crear la cuenta administradora (nombre, correo y contraseña). No se incluyen cuentas ni contraseñas por defecto. El correo indicado recibirá los códigos de seguridad.

Para detener el servidor, cierra la ventana o presiona `Ctrl+C`.

> El servidor escucha únicamente en `127.0.0.1`; no está pensado para publicarse en internet.

## Verificación en dos pasos

- Si `correo_config.json` tiene un Gmail y una contraseña de aplicación válidos, el código de 6 dígitos se envía al correo de la cuenta.
- Si no está configurado, el servidor funciona en **modo prueba** y muestra el código en la propia pantalla de login.
- El código vence en 5 minutos, es de un solo uso y admite máximo 3 intentos.
- Si la página se abre sin servidor (`file://`), se genera un código local en el navegador para no bloquear el acceso.

Para activar el envío real, copia `correo_config.example.json` como `correo_config.json` y completa:

```json
{
  "correo": "tu_correo@gmail.com",
  "clave_aplicacion": "los_16_caracteres_de_la_clave_de_aplicacion",
  "asistente": "ProGanado Seguridad <tu_correo@gmail.com>"
}
```

`correo_config.json` está excluido de Git para no publicar credenciales. El repositorio solo incluye la plantilla con marcadores de posición.

## Datos y copias de seguridad

- La base principal es `datos/proganado.sqlite3` y está excluida de Git.
- Las fotos de facturas se guardan en la misma base SQLite cuando el servidor está activo; sin servidor se usa IndexedDB del navegador.
- Las fotos nuevas de animales se guardan en el almacén binario del servidor con el prefijo `bov_`. Si el servidor no está disponible, se guarda una versión comprimida junto al registro en `localStorage`.
- También se conserva una copia de trabajo en `localStorage` para que la app siga funcionando si el servidor no responde.
- Para respaldar: detén el servidor y copia la carpeta `datos/` y, si usas la app sin servidor, exporta la información desde el navegador.
- No borres `datos/proganado.sqlite3` al actualizar el código.

## Estructura

```
index.html               Interfaz: login, panel y diálogos
proganado.css            Estilos de la aplicación
proganado.js             Autenticación, datos, renderizado, CSV y PDF
servidor.py              Servidor local, API de datos, fotos y 2FA
Iniciar ProGanado.bat    Arranque con un clic en Windows
correo_config.example.json  Plantilla de configuración de Gmail
assets/                  Logos, fotos, fuentes y una foto por animal
assets/ganado/           Fotos del inventario (vaca_<arete>.jpg)
SEGURIDAD.md             Medidas y límites de seguridad
```

## Seguridad

Las contraseñas se derivan con PBKDF2-SHA256 (150 000 iteraciones) y salt único. Los hashes antiguos SHA-256 se migran automáticamente al iniciar sesión. Hay bloqueo temporal tras 5 intentos fallidos y la sesión puede durar 7 días si se marca «Mantener sesión».

Revisa [SEGURIDAD.md](SEGURIDAD.md) para conocer las protecciones incluidas y las limitaciones de una aplicación local.

## Notas

- Los datos del hato son locales: no se envían a servicios externos.
- La aplicación no sustituye los registros oficiales exigidos por el ICA ni el asesoramiento veterinario.
- Las cuentas se administran desde **Usuarios**. Usa contraseñas distintas por persona y elimina las cuentas que ya no se necesiten.
