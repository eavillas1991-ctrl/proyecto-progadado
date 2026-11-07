# Seguridad de ProGanado

ProGanado es una aplicación **local**: el servidor escucha solo en `127.0.0.1` y los datos permanecen en el equipo de la finca. Este documento resume las protecciones implementadas y los límites que deben tenerse presentes.

## Protecciones incluidas

### Autenticación y sesiones

- Contraseñas derivadas con **PBKDF2-SHA256** (150 000 iteraciones) y salt único por cuenta.
- Migración automática de hashes antiguos SHA-256 al iniciar sesión correctamente.
- Bloqueo temporal de 5 minutos tras 5 intentos fallidos.
- Verificación en dos pasos (2FA) con código de 6 dígitos:
  - vigencia de 5 minutos;
  - un solo uso;
  - máximo 3 intentos;
  - espera mínima de 20 segundos entre reenvíos al mismo correo;
  - comparación en tiempo constante.
- Sesión de 7 días solo si el usuario marca «Mantener sesión»; de lo contrario dura lo que la pestaña.
- Roles diferenciados: el administrador gestiona cuentas y eliminaciones; el usuario operativo consulta y registra información.
- Límite de 4 administradores y 7 usuarios operativos.

### Interfaz y contenido

- Política CSP restrictiva: scripts solo del propio sitio, sin recursos remotos ni scripts en línea.
- Sin dependencias externas, analítica ni llamadas a servicios de terceros.
- Datos dinámicos escapados antes de insertarse como HTML en las tablas y tarjetas.
- Exportaciones CSV protegidas contra inyección de fórmulas.
- Validación de campos y fechas antes de guardar.

### Servidor local

- Escucha exclusivamente en `127.0.0.1`.
- Cabeceras de seguridad: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` y CSP.
- Bloqueo de archivos sensibles (`.py`, `.json`, `.bat`, `.md`, bases de datos y archivos ocultos).
- Sin listado de directorios: solo se sirven archivos concretos.
- Límites de tamaño para la base (50 MB), fotos (15 MB) y peticiones JSON (64 KB).
- La base de datos y las facturas se guardan fuera del alcance de la web, en `datos/`.
- Fotografías de facturas servidas como `image/jpeg` con longitud explícita.

## Límites importantes

- **No es una aplicación para internet.** No hay HTTPS, proxy inverso, firewall de aplicación ni aislamiento de red. Debe ejecutarse en un equipo de confianza y no exponerse a la red.
- **La autenticación es del lado del cliente.** Las cuentas y sus hashes viven en `localStorage`; la API local no exige un token de sesión. Cualquier proceso con acceso al mismo equipo podría leer o modificar los datos.
- **Sin cifrado en reposo.** SQLite y `localStorage` no cifran la información. Quien tenga acceso al disco o al perfil del navegador puede leerla.
- **Cuentas iniciales.** No se incluyen cuentas ni contraseñas por defecto. En el primer arranque se crea la cuenta administradora desde la pantalla de acceso; usa el correo del responsable, porque allí llegarán los códigos 2FA.
- **El modo prueba muestra el código 2FA en pantalla.** Es cómodo para uso local, pero no debe usarse como seguridad real frente a terceros.
- **Sin registro de auditoría ni copias automáticas.** No hay historial de accesos ni respaldo programado; las copias debe hacerlas el responsable.
- **Riesgo residual de XSS.** Se escapan los datos al renderizar, pero cualquier cambio futuro que vuelva a insertar texto sin escapar puede reintroducir el problema.
- **Si el repositorio estuvo público con credenciales antiguas**, esas contraseñas deben considerarse comprometidas aunque el historial se haya limpiado después. Cámbialas y revisa el acceso a la cuenta de Gmail.

## Buenas prácticas recomendadas

1. Usar contraseñas distintas por persona y cambiarlas periódicamente.
2. Mantener `correo_config.json` fuera de Git (ya está ignorado) y usar una contraseña de aplicación de Gmail, nunca la contraseña principal.
3. Ejecutar el servidor solo cuando se use la aplicación y cerrarlo al terminar.
4. Respaldar `datos/` con regularidad y guardar la copia en otro medio.
5. No abrir el puerto 8899 en el router ni publicar la carpeta del proyecto en un servidor web.
6. Revisar periódicamente las cuentas activas y eliminar las que ya no se usen.

## Reporte de problemas

Si encuentras una vulnerabilidad, no publiques datos reales ni credenciales en un issue. Contacta al responsable del repositorio y describe el problema de forma privada.
