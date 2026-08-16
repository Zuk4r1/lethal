# ⚔️ LETHAL IDOR + CSRF EXPLOITER v3.0

Herramienta ofensiva para automatizar detección y explotación de **IDOR**
(Insecure Direct Object Reference), **BOLA/Broken Access Control** y
**CSRF** en programas de Bug Bounty, VDPs y pentests autorizados.

Esta es una reescritura de la v2.1 tras una auditoría técnica completa
(ver `AUDIT.md`). El cambio más importante: en v2.1 el repo tenía dos
codebases en paralelo (`lethal.py` y `core/`) que nunca se conectaban
entre sí, y el binario real corría con la lógica más simple y frágil.
En v3.0 hay **un solo codebase real**: `lethal.py` es el CLI, toda la
lógica vive en `core/` y se importa.

---

## Qué cambió respecto a v2.1

| Área | v2.1 | v3.0 |
|---|---|---|
| Arquitectura | `core/` desconectado (código muerto) | `lethal.py` importa `core/`, un solo codebase |
| Instalación | `requirements.txt` roto (`core.utils`, `uuid` como paquetes PyPI) | `pip install -r requirements.txt` limpio |
| Detección bloqueo/vulnerable | diff de longitud `<20 chars` | similarity ratio (`difflib`) sobre texto normalizado |
| Modo Autorize | igualdad exacta de string (falsos negativos con tokens/nonces) | similarity ratio + chequeo de si el usuario alt fue realmente denegado |
| Ejecución | 100% secuencial | `ThreadPoolExecutor` concurrente + rate limiting adaptativo en 429 |
| Conexión HTTP | `requests.request()` suelto por cada llamada | `requests.Session()` persistente + reintentos automáticos |
| Evidencia | solo tabla de texto | JSON con request/response completos por hallazgo + borrador de reporte Markdown |
| Patrones IDOR/CSRF | hardcodeados y duplicados en 2 archivos | `config/patterns.yaml`, editable sin tocar código |
| Headers "anti-WAF" | vendidos como evasión general | documentados como prueba específica de IP-trust bypass (CWE-290) |
| Tests | 0 | 19 tests unitarios (`pytest`) sobre el motor de detección, parser y CSRF |

## 🚀 Instalación

```bash
git clone https://github.com/Zuk4r1/lethal.git
cd lethal
pip install -r requirements.txt
```

## 🛠️ Uso

### IDOR (con evidencia y reporte automático)
```bash
python3 lethal.py --url "https://target.com/api/user?id=123" --param id \
  --ids ids.txt --method GET --threads 15 --report
```
Genera:
- `output/resultados.txt` — tabla de resultados
- `output/evidence/*.json` — request/response completos de cada hallazgo vulnerable
- `output/reporte_idor_*.md` — borrador de reporte listo para pulir y enviar

### Autorize (bypass de control de acceso entre dos usuarios/tokens)
```bash
python3 lethal.py --url "https://target.com/api/resource?user_id=123" --param user_id \
  --ids ids.txt --method GET --autorize \
  --header "Authorization: Bearer TOKEN_A" \
  --alt-header "Authorization: Bearer TOKEN_B"
```

### Intruder (fuzzing de un parámetro con payloads propios)
```bash
python3 lethal.py --url "https://target.com/api?param=1" --param param \
  --intruder --payload-list payload-list.txt --threads 15
```

### Desde export de Burp Suite (XML o JSON)
```bash
python3 lethal.py --url "https://target.com" --burp-json logs_burp.json --ids ids.txt
python3 lethal.py --url "https://target.com" --burp-logs logs_burp.xml --ids ids.txt
```

### Detección estática de CSRF
```bash
python3 lethal.py --url "https://target.com/api/transfer" --method POST \
  --header "Cookie: session=abc123"
```
Para generar un PoC de auto-submit form o fetch(), usar
`core.csrf.generar_poc_html()` / `generar_poc_fetch()` desde un script
propio o el REPL -- ver `core/csrf.py`.

## ⚙️ Parámetros

```
--url URL              URL objetivo con ?param=ID o endpoint (requerido)
--param PARAM           Parámetro de ID para IDOR/Autorize/Intruder
--ids IDS               Archivo con IDs
--method METHOD         Método HTTP (default: GET)
--header HEADER         Cabeceras: 'Key: Value' (repetible)
--alt-header ALT_HEADER Cabeceras alternativas para --autorize
--forbidden FORBIDDEN   Texto que indica acceso denegado
--proxy PROXY           Proxy tipo http://127.0.0.1:8080 (Burp Suite)
--threads N             Peticiones concurrentes (default: 10, nuevo en v3.0)
--timeout N             Timeout por petición en segundos (default: 10)
--silent                Sin banners, solo resultados
--no-evidence           No guardar evidencia cruda (por defecto SÍ se guarda)
--report                Generar borrador de reporte Markdown
--autoidor              Extraer parámetros IDOR desde examples/burp_logs.txt
--burp-logs PATH        Export XML de Burp Suite
--burp-json PATH        Export JSON de Burp Suite
--autorize              Modo Autorize
--intruder              Modo Intruder
--payload-list PATH     Payloads para --intruder
```

## 📂 Estructura

```
lethal.py              CLI (solo orquestación, argparse)
core/
  config.py             Carga de config/patterns.yaml
  detection.py           Motor de similarity ratio (reemplaza diff de longitud)
  http_client.py          Session, retries, rate limiting, headers de prueba
  idor.py                  Modo IDOR concurrente
  autorize.py               Modo Autorize concurrente
  intruder.py                Modo Intruder concurrente
  burp_parser.py              Parsers de export Burp XML/JSON
  csrf.py                      Detección CSRF + generación de PoC HTML/fetch
  evidence.py                   Captura de evidencia + reporte Markdown
  utils.py                       Banner, carga de archivos, tablas
config/patterns.yaml    Patrones IDOR/CSRF editables sin tocar código
examples/               Datos de ejemplo sintéticos (no reales)
tests/                  Suite pytest (19 tests)
```

## 🧪 Tests

```bash
pip install pytest
pytest tests/ -v
```

## 🔒 Disclaimer

Esta herramienta ha sido desarrollada exclusivamente para fines educativos y de investigación ética. El uso indebido en sistemas sin autorización es ilegal y no se responsabiliza al autor por daños ocasionados.

Siempre prueba con permiso explícito. Respeta la ley. Sé un hacker ético.

## ❤️ Créditos

> Autor: [Zuk4r1](https://github.com/Zuk4r1)
> 
> Versión: 3.0 — refactor post-auditoría
> 
> Licencia: MIT

## ☕ Apoya mis proyectos

Si te resultan útiles mis herramientas, considera dar una ⭐ en GitHub o invitarme un café. ¡Gracias!

[![Buy Me A Coffee](https://img.shields.io/badge/Buy_Me_A_Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/investigacq)  [![PayPal](https://img.shields.io/badge/PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white)](https://www.paypal.me/yordansuarezrojas)
