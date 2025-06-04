# ⚔️ LETHAL IDOR + CSRF EXPLOITER v2.1

Herramienta ofensiva avanzada para explotación automatizada de vulnerabilidades **IDOR** y **CSRF** **LETHAL IDOR + CSRF EXPLOITER v2.1** es una herramienta diseñada para profesionales de la **seguridad ofensiva** — **Bug Bounty hunters**, **Red Team operators** y **Pentesters avanzados** — que buscan automatizar la explotación de dos de las vulnerabilidades más críticas y frecuentes en entornos web: **IDOR (Insecure Direct Object Reference)** y **CSRF (Cross-Site Request Forgery)**.

---

## 🚀 Características principales:

- **Automatización completa del flujo de explotación IDOR:** identifica y explota endpoints vulnerables mediante manipulación de IDs, UUIDs, hashes o tokens expuestos.

- **Módulo ofensivo de CSRF:** genera múltiples vectores modernos de explotación, incluyendo:

## Auto-submit forms.

🌐 Ataques vía fetch() y XMLHttpRequest.

📜 Inclusión en iframes y formularios ocultos.

⚙️ Payloads persistentes con XSS encadenado.

💥 Explotación de debilidades en la política SameSite.

🕵️‍♂️ Modo Ninja Stealth: técnicas de evasión para WAFs, detección de bots, restricciones CORS y validaciones anti-automatización.

🔄 Modo **"autorize"** avanzado 🔐: compara dinámicamente las respuestas entre usuarios autenticados y no autenticados (o con roles distintos) para identificar fallos de control de acceso, bypasses de autorización o diferencias lógicas en los permisos.

💣 Modo **"intruder"** ofensivo 🧨: realiza ataques masivos y agresivos contra múltiples parámetros o endpoints, inyectando patrones automatizados, fuzzing de IDs y análisis de comportamiento en respuesta para detección rápida de IDOR ocultos

**Modo Ninja Stealth:** técnicas de evasión para entornos con WAFs, restricciones CORS o detección de automatización.

- Soporte para múltiples objetivos (multi-URL, multi-usuario, multi-victim).

- Simulación de múltiples roles (admin, user, guest) para análisis de privilegios.

- Exportación de exploits listos para enviar en reportes de Bug Bounty, con vectores visuales y ejemplos funcionales.

## 🎯 Casos de uso:

- Explotación de endpoints con referencias inseguras a objetos (/user/1234, /order/abcde, etc.).

- Verificación de bypass de controles de acceso horizontal y vertical.

## ⚙️ Generación de CSRF para:

- Cambios de contraseña sin autenticación.

- Transferencias de dinero sin validación.

- Eliminación de cuentas.

- Cambio de correo u otros datos críticos.

- Automatización de ataques secuenciales: detección IDOR ➝ generación de exploit CSRF ➝ ejecución ➝ generación de reporte.

## 🧠 Inteligencia ofensiva:

- Análisis dinámico de respuestas HTTP para detectar errores de autorización o filtrados.

- Detección de tokens anti-CSRF (y bypass si es posible).

- Recolección de víctimas potenciales mediante análisis de tráfico, Wayback Machine o directorios públicos.

- Soporte para entornos API REST y SPA (Single Page Apps).

## 📦 Integración y personalización:

- Compatible con Burp Suite (extensión / integración).

- Módulos exportables como PoC en HTML, JS, Markdown o PDF.

- Personalización de payloads, headers y métodos HTTP.

Esta herramienta no solo explota vulnerabilidades: las transforma en pruebas de concepto profesionales listas para ser reportadas, maximizando el impacto y la calidad técnica del hallazgo. Ideal para quienes buscan ir más allá del escaneo superficial y demostrar compromiso con el arte del hacking ético de alto nivel.

---

## 🚀 Instalación

```bash
git clone https://github.com/Zuk4r1/lethal-idor-csrf-exploiter.git
cd lethal-idor-csrf-exploiter
pip install -r requirements.txt
```

## 🛠️ Uso básico
🧬 Extracción de parámetros sospechosos (desde Burp)

```bash
python3 lethal.py --url "https://target.com/api/user?id=123"--burp-logs burp_logs.txt
```

## 💣 Explotación IDOR (con payloads agresivos)

```bash
python3 lethal.py --url "https://target.com/api/user?id=123" --param id --ids ids.txt --method GET --forbidden "acceso denegado"
```

## 🔐 Ataque CSRF/Login con token

```bash
python3 lethal.py --url "https://target.com/api/login" --email "victima@example.com" --password "123456" --token "tok-abcdef" --code "000000" --redirect "https://target.com/dashboard"
```

## 🔐 El modo "autorize" avanzado

```bash
python lethal.py --url "https://target.com/api/resource?user_id=123" --param user_id --ids ids.txt --method GET --header "Authorization: Bearer TOKEN" --autorize --alt-header "Authorization: Bearer OTRO_TOKEN"
```

## 🧨  El modo "intruder" avanzado

```bash
python lethal.py --url "https://objetivo.com/api?param=1" --param param --intruder --payload-list payloads.txt
```

## ⚙️ Parámetro	Descripción

```bash
python lethal.py -h

usage: lethal.py [-h] --url URL [--param PARAM] [--ids IDS] [--method METHOD] [--header HEADER] [--forbidden FORBIDDEN]
                 [--proxy PROXY] [--email EMAIL] [--password PASSWORD] [--code CODE] [--redirect REDIRECT] [--token TOKEN]
                 [--autoidor] [--silent] [--burp-logs BURP_LOGS] [--burp-json BURP_JSON] [--payloads PAYLOADS]
                 [--autorize] [--alt-header ALT_HEADER]

⚔ Herramienta Definitiva IDOR + CSRF Exploiter

options:
  -h, --help            show this help message and exit
  --url URL             URL objetivo con ?param=ID o endpoint login (default: None)
  --param PARAM         Parámetro de ID para IDOR (default: None)
  --ids IDS             Archivo con IDs (default: None)
  --method METHOD       Método HTTP (default: GET)
  --header HEADER       Cabeceras personalizadas: 'Key: Value' (default: None)
  --forbidden FORBIDDEN Texto que indica acceso denegado (default: Access Denied)
  --proxy PROXY         Proxy tipo http://127.0.0.1:8080 (Burp Suite) (default: None)
  --email EMAIL         Email válido (default: None)
  --password PASSWORD   Password válida (default: None)
  --code CODE           Verification Code (default: None)
  --redirect REDIRECT   Redirect URL (default: None)
  --token TOKEN         Token válido para autenticación (default: None)
  --autoidor            Extraer automáticamente parámetros IDOR desde logs de Burp (default: False)
  --silent              Modo Red Team Silencioso: sin banners ni mensajes, solo resultados en .txt (default: False)
  --burp-logs BURP_LOGS Archivo XML exportado de Burp Suite para detección automática de endpoints vulnerables (default: None)
  --burp-json BURP_JSON Archivo JSON exportado de Burp Suite para detección automática de endpoints vulnerables (default: None)
  --payloads PAYLOADS   Archivo JSON con payloads avanzados (default: None)
  --autorize            Prueba avanzada de autorización (tipo Autorize) (default: False)
  --intruder            Ataque tipo intruder/fuzzing sobre un parámetro usando payloads personalizados (default: False)
  --payload-list        Archivo con lista de payloads para intruder (default: None)
  --alt-header ALT_HEADER
                        Cabeceras alternativas para usuario/cookie/token alternativo: 'Key: Value' (default: None)
```

## 📂 Estructura de salida

output/resultados.txt: tabla con cada intento, resultado HTTP y posible vulnerabilidad.

Soporte para exportar más detalles y logs completos en próximas versiones.

## 🔒 Disclaimer

Esta herramienta ha sido desarrollada exclusivamente para fines educativos y de investigación ética. El uso indebido en sistemas sin autorización es ilegal y no se 
responsabiliza al autor por daños ocasionados.

Siempre prueba con permiso explícito. Respeta la ley. Sé un hacker ético.

# 🤝 Contribuciones

Se aceptan pull requests, mejoras de código, integración con más fuentes OSINT y módulos de detección avanzados.
  <br />
	<br/>
      	<p width="20px"><b>Se aceptan donaciones para mantener este proyecto</p></b>
	      <a href="https://buymeacoffee.com/investigacq"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=investigacqc&button_colour=FF5F5F&font_colour=ffffff&font_family=Cookie&outline_colour=000000&coffee_colour=FFDD00" /></a><br />
      	<a href="https://www.paypal.com/paypalme/babiloniaetica"><img title="Donations For Projects" height="25" src="https://ionicabizau.github.io/badges/paypal.svg" /></a>
</div>

## ❤️ Créditos

> Autor: [Zuk4r1](https://github.com/Zuk4r1)  
> Versión: 2.1 – 2025  
> Licencia: MIT  
> Uso exclusivo para investigación ética y entornos controlados.
> Sígueme para más herramientas de Red Team y Bug Bounty.

# ¡Feliz hackeo! 🎯
