# Seguridad de ProGanado

Esta entrega funciona sin servidor y guarda los datos en el navegador del equipo.

Protecciones incluidas:

- Política CSP que restringe scripts, estilos, imágenes y formularios al propio paquete.
- Sin dependencias, fuentes, analítica ni recursos remotos.
- Validación estricta de todos los campos del animal.
- Renderizado mediante DOM seguro, sin insertar datos como HTML.
- Límite de 500 registros cargados desde el almacenamiento local.
- Exportación CSV protegida contra inyección de fórmulas.

Límite importante:

El almacenamiento local no cifra la información ni ofrece usuarios, permisos, auditoría o copias de seguridad. Para una aplicación publicada o usada por varias personas se requiere un backend con HTTPS, autenticación multifactor, roles, base de datos cifrada, registro de auditoría, copias de seguridad y revisiones periódicas de dependencias.
