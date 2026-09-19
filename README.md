# proyecto-progadado

ProGanado · Gestión Ganadera — página local de gestión del hato (salud, reproducción, producción, potreros PRV y usuarios).

## Uso
Doble click en `Iniciar ProGanado.bat` o:

```bat
python servidor.py
```

Luego abre http://127.0.0.1:8899/index.html

## Estructura
- `index.html` — login + panel principal
- `styles.css`, `auth.css`, `enhancements.css`, `funciones.css` — estilos
- `app.js`, `auth.js` — lógica del panel y login 2FA
- `servidor.py` — servidor local (página + códigos al correo)
- `correo_config.json` — configuración del correo (sin claves reales)
- `assets/` — logos e imágenes
