# Auditoría técnica — LETHAL IDOR + CSRF EXPLOITER v2.1
Repositorio: `github.com/Zuk4r1/lethal` (rama `main`) — 2997 líneas Python, 8 módulos.

## Resumen ejecutivo

El proyecto tiene una idea sólida (automatizar IDOR + CSRF + Autorize + Intruder a partir de exports de Burp), pero en el estado actual del repo hay **una desconexión arquitectónica crítica**: `lethal.py` (el entrypoint real, el único que se ejecuta) no importa nada de `core/`. Todo lo "avanzado" — analyzer, baseline, csrf_exploit, headers, parser, utils (2000+ líneas) — es **código muerto**. Lo que realmente corre en producción es la lógica más simple, duplicada dentro de `lethal.py`. Esto explica por qué el README promete cosas (fetch/XHR CSRF vectors, análisis de sesiones, generación de PoC HTML/JS/MD) que el binario no hace.

Prioridad de arreglo: **1) reconectar o eliminar `core/` → 2) arreglar instalación → 3) motor de detección de diffs → 4) concurrencia y evidencia para reporting.**

---

## Hallazgos críticos

### 1. `core/` está completamente desconectado — CRÍTICO
```
lethal.py:  (sin "from core." en ningún import)
core/baseline.py:      from core.parser import (...)
core/csrf_exploit.py:  from core.utils import guardar_resultado
core/idor_exploit.py:  from core.utils import guardar_resultado
```
`core/idor_exploit.py` tiene `contiene_bypass()`, `respuestas_similares()`, `contiene_datos_sensibles()` — versiones más maduras de lo que hay hardcodeado en `lethal.py` (`es_bloqueada`, `detect_sensitive_info`). `core/parser.py` tiene extracción real de tokens CSRF desde HTML (`extraer_tokens_csrf`, `detectar_formularios`) usando BeautifulSoup — esto es justo lo que falta en `lethal.py`, que **nunca parsea el HTML de respuesta**, solo compara texto crudo.

**Impacto:** estás manteniendo dos codebases en paralelo. Cualquier mejora que hagas en `core/` no llega al binario que usas. El "Autorize avanzado" y "modo intruder" del README corren con la lógica simple, no con `idor_exploit.py`.

**Fix:** decide una de dos rutas y bórralo o intégralo, no dejes ambas:
- **Ruta A (recomendada):** hacer que `lethal.py` sea solo el CLI (argparse) y mover toda la lógica a `core/`, importándola. Esto también resuelve el problema de testear (ver punto 8).
- **Ruta B:** si `core/` es un prototipo abandonado, bórralo del repo — ahora mismo es ruido que confunde a cualquiera (incluido tú en 6 meses) sobre qué código es el real.

### 2. `requirements.txt` está roto — CRÍTICO (bloqueante)
```
requests
beautifulsoup4
urllib3
colorama
termcolor
tqdm
lxml
html5lib
pyyaml
bs4
core.utils     <-- no es un paquete de PyPI, es tu propio módulo local
uuid           <-- stdlib, no se instala con pip; con pip modernos falla
prettytable
```
`pip install -r requirements.txt` va a intentar resolver `core.utils` contra PyPI y fallará (o, peor, si algún día alguien registra un paquete malicioso llamado `core-utils`/`uuid` en PyPI vía typosquatting, lo instalarías sin darte cuenta — esto es exactamente el vector de ataque de dependency confusion). `uuid` es stdlib desde Python 2.5; listarlo es inofensivo pero ruidoso, `core.utils` es el problema real.

**Fix:**
```
requests
beautifulsoup4
urllib3
colorama
termcolor
tqdm
lxml
html5lib
pyyaml
prettytable
```

### 3. Detección de "bloqueado vs. vulnerable" es débil — ALTO (falsos positivos/negativos)
```python
if baseline_len is not None:
    diff = abs(len(resp.text) - baseline_len)
    if diff < 20:
        return True, "Longitud similar a acceso denegado"
```
Comparar por **longitud de texto con un margen fijo de 20 caracteres** es la parte más frágil de toda la herramienta, porque:
- Falsos negativos: una API que devuelve JSON con timestamps, IDs incrementales o nombres de campos de longitud variable puede diferir en cientos de bytes entre "denegado" y "autorizado" sin que signifique nada — o al revés, dos respuestas de objetos distintos con `user_id` de igual longitud (`1001` vs `1002`) pasan el filtro de "similar" y se reportan como bloqueadas aunque sean datos de otro usuario.
- Falsos positivos: contenido dinámico (CSRF token, nonce, fecha) hace que la respuesta "autorizada" nunca tenga exactamente la misma longitud dos veces, disparando "vulnerable" cuando en realidad es ruido.

En `autorize_advanced()` el problema es aún mayor porque usas **igualdad exacta de string**:
```python
if resp_auth.text.strip() == resp_alt.text.strip():
```
Cualquier token, timestamp o header eco en el body rompe la comparación y genera un falso negativo — te vas a perder bypasses reales de autorización porque las dos respuestas "difieren" en un campo irrelevante.

**Fix recomendado:** reemplazar longitud/igualdad por *similarity ratio* con `difflib.SequenceMatcher`, normalizando antes de comparar (quitar campos volátiles conocidos vía regex: timestamps ISO, UUIDs, tokens JWT/CSRF, contadores de request-id):
```python
import difflib, re

VOLATILE = [
    re.compile(r'"?(csrf|xsrf|token|nonce|request[_-]?id)"?\s*[:=]\s*"?[\w\-\.]+"?', re.I),
    re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?'),  # ISO timestamps
]

def normalizar(texto):
    for pat in VOLATILE:
        texto = pat.sub("__VOL__", texto)
    return texto

def similitud(a, b):
    return difflib.SequenceMatcher(None, normalizar(a), normalizar(b)).ratio()

# en vez de diff < 20:
if similitud(resp.text, baseline_text) > 0.92:
    return True, f"Contenido {similitud(resp.text, baseline_text)*100:.1f}% similar al baseline"
```
Umbral configurable por `--similarity-threshold` (default 0.90–0.95), y loguear el ratio en la tabla de resultados en vez de solo Sí/No — así puedes ordenar por "más sospechoso primero" cuando hay cientos de IDs.

### 4. Todo es secuencial — ALTO (no escala a bug bounty real)
`explotar_idor` hace `for id in id_list: for payload in advanced_payloads(id):` con `sleep_jitter(0.1, 0.7)` **por cada request**, secuencial. Con `ids.txt` de 388KB (miles de líneas, según el tamaño del archivo en tu propio repo) y ~15 variantes de payload por ID en `advanced_payloads()`, estás ante decenas de miles de requests secuenciales — horas de escaneo para un solo endpoint.

**Fix:** `concurrent.futures.ThreadPoolExecutor` con límite de workers configurable (`--threads`, default 10) + rate limiting adaptativo que baje la concurrencia si detecta 429:
```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def explotar_idor_concurrente(url, param_name, id_list, headers, forbidden_signature,
                                method, proxy=None, silent=False, threads=10):
    proxies = {"http": proxy, "https": proxy} if proxy else None
    baseline_resp, baseline_len = obtener_baseline_denegado(url, param_name, headers, forbidden_signature, method, proxy)
    baseline_text = baseline_resp.text if baseline_resp else ""

    payloads_totales = [(id_, p) for id_ in id_list for p in advanced_payloads(id_)]
    resultados = []
    rate_limit_hit = threading.Event()

    def probar(id_payload):
        _, payload = id_payload
        if rate_limit_hit.is_set():
            time.sleep(random.uniform(2, 5))  # backoff global si ya vimos 429
        objetivo = construir_url(url, param_name, payload)
        req_headers = advanced_bypass_headers(headers.copy() if headers else None)
        try:
            resp = requests.request(method=method, url=objetivo, headers=req_headers,
                                     proxies=proxies, timeout=10)
            if resp.status_code == 429:
                rate_limit_hit.set()
            bloqueada, razon = es_bloqueada_similitud(resp, forbidden_signature, baseline_text)
            return {"id": payload, "status": resp.status_code,
                    "desc": razon, "vulnerable": not bloqueada}
        except Exception as e:
            return {"id": payload, "status": "ERROR", "desc": str(e), "vulnerable": False}

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(probar, ip) for ip in payloads_totales]
        for f in as_completed(futures):
            resultados.append(f.result())
    return resultados
```
Esto baja un escaneo de horas a minutos y además el `rate_limit_hit.set()` te da evasión *real* basada en la respuesta del servidor, en vez de headers `X-Forwarded-For` falsos que no engañan a ningún WAF moderno (ver punto 5).

### 5. Los headers "anti-WAF" no evaden nada moderno — MEDIO
```python
"X-Forwarded-For": f"127.0.0.{random.randint(2,254)}",
"X-Remote-IP": f"127.0.0.{random.randint(2,254)}",
"X-Host": "localhost",
```
Esto solo funciona contra apps mal configuradas que confían ciegamente en headers de cliente para IP allowlisting (útil de hecho para *probar* ese bug específico — pero no es "evasión de WAF" en general, es una prueba de *IP spoofing / trust boundary bypass*). Cualquier WAF real (Cloudflare, AWS WAF, Akamai) ignora estos headers para su propio rate-limiting porque usa la IP TCP real. Documentarlo así en el README genera expectativas falsas sobre qué hace la herramienta.

**Fix de framing, no de código:** renombra la función a algo como `headers_trust_boundary_probe()` y documenta que sirve para testear *IP-based access control bypass* (un hallazgo válido y reportable en sí mismo: CWE-290), no como evasión general de detección de bot.

### 6. Sin captura de evidencia cruda → reportes débiles — MEDIO
`log_resultados()` solo escribe la tabla PrettyTable a texto plano. Para un reporte aceptado en H1/Bugcrowd necesitas la request y response completas (headers incluidos) del hallazgo, no solo "status 200, longitud 512". Ahora mismo tendrías que reproducir manualmente cada hit para armar el PoC.

**Fix:** guardar por cada resultado `vulnerable=True` un artefacto JSON con request/response completos, y generar un PoC Markdown listo para pegar en el reporte:
```python
def guardar_evidencia(resultado, req, resp, outdir="output/evidence"):
    os.makedirs(outdir, exist_ok=True)
    slug = re.sub(r'\W+', '_', str(resultado["id"]))[:40]
    with open(f"{outdir}/{slug}.json", "w") as f:
        json.dump({
            "request": {"method": req.method, "url": req.url,
                        "headers": dict(req.headers), "body": req.body},
            "response": {"status": resp.status_code,
                         "headers": dict(resp.headers),
                         "body": resp.text[:5000]},
            "veredicto": resultado["desc"],
        }, f, indent=2)
```
Y una función `generar_reporte_markdown(resultados_vulnerables)` que arme el bloque `Title/Summary/Steps to reproduce/Impact/Severity/Recommendation` automáticamente desde esos JSON — esto es exactamente el "exportación de exploits listos para reportes" que promete el README pero que hoy no existe en `lethal.py`.

### 7. `global advanced_payloads` — antipatrón frágil — MEDIO
```python
global advanced_payloads
if args.payloads:
    custom_payloads = load_payloads(args.payloads)
    advanced_payloads = lambda id_value: [p.replace("FUZZ", str(id_value)) for p in custom_payloads]
```
Reasignar una función global en `main()` funciona pero es frágil: si en el futuro divides el código en módulos (punto 1), esto se rompe silenciosamente porque el `global` solo afecta al namespace de `lethal.py`. Además complica testing (no puedes instanciar dos configuraciones de payloads en la misma sesión de Python, p. ej. para tests unitarios).

**Fix:** pasar la función de payloads como parámetro explícito a `explotar_idor(..., payload_fn=advanced_payloads)` en vez de mutar el global.

### 8. Cero tests — MEDIO
2997 líneas sin un solo test. `es_bloqueada`, `detect_sensitive_info`, `analizar_param` (regex de IDOR) y el parser de Burp XML/JSON son candidatos perfectos para `pytest` con fixtures de respuestas HTTP grabadas — esto además te protege de que un refactor (como el del punto 1, mover todo a `core/`) rompa la detección sin que te des cuenta.

### 9. Fixture de ejemplo con JSON inválido — BAJO
`logs_burp_REAL.json` (dato de ejemplo, no un leak — usa `target-site.com` / `valid_token_here`, confirmado) tiene una coma sobrante que rompe el parseo estándar (`json.decoder.JSONDecodeError` al cargarlo con `json.load`). Si alguien usa ese archivo como ejemplo de referencia para `--burp-json`, va a fallar. Vale la pena moverlo a una carpeta `examples/` y validarlo con `python -m json.tool` en CI.

---

## Roadmap priorizado

| # | Mejora | Esfuerzo | Impacto en hallazgos reales |
|---|--------|----------|------------------------------|
| 1 | Reconectar `core/` a `lethal.py` (o eliminar `core/`) | Medio | Alto — dejas de mantener 2 codebases |
| 2 | Arreglar `requirements.txt` | Trivial | Bloqueante — sin esto el `pip install` del README falla |
| 3 | Similarity ratio (`difflib`) en vez de diff de longitud/igualdad exacta | Medio | Alto — reduce falsos positivos/negativos en IDOR y Autorize |
| 4 | Concurrencia (`ThreadPoolExecutor`) + backoff en 429 | Medio | Alto — pasa de horas a minutos por target |
| 5 | Captura de evidencia cruda + generador de PoC Markdown | Medio | Alto — reportes más rápidos y con mejor tasa de aceptación |
| 6 | `requests.Session()` + `urllib3.Retry` para reintentos/conexión persistente | Bajo | Medio — menos ruido de errores de red falsos |
| 7 | Externalizar patrones IDOR/CSRF (`analyzer.py`) a YAML (ya tienes `pyyaml`) | Bajo | Medio — puedes ajustar patrones sin tocar código |
| 8 | Tests unitarios (`pytest`) para el motor de detección | Medio | Medio — evita regresiones al refactorizar |
| 9 | Reframe de headers "anti-WAF" como prueba de IP trust bypass | Trivial | Bajo (documentación, evita falsas expectativas) |

---

## Nota de OPSEC
`logs_burp_masivo.xml` y `logs_burp_REAL.json` en el repo usan datos sintéticos (`target-site.com`) — no hay leak de un target real. Aun así, como hábito para un repo público de bug bounty: cualquier captura de Burp que uses para testing con targets reales (tokens `Authorization: Bearer ...`, cookies de sesión, IDs de usuarios reales) nunca debería llegar a un commit, ni siquiera en una rama vieja — un `git filter-repo` no es suficiente si ya se hizo push; hay que rotar cualquier credencial expuesta. Vale la pena añadir `*.burp`, `logs_burp_*.json`, `logs_burp_*.xml` reales (no los de ejemplo) a `.gitignore` para evitar subirlos por accidente en el futuro.
