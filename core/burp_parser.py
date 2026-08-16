"""
Extracción de endpoints/parámetros sospechosos desde exports de Burp
Suite (XML o JSON). Misma lógica que la v2.1 pero usando los keywords de
config/patterns.yaml en vez de una regex duplicada hardcodeada, y con
manejo de errores explícito que reporta línea/motivo en vez de fallar en
silencio.
"""
import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs

from core.config import CONFIG


def extraer_idors_desde_logs(path, silent=False):
    """Extrae nombres de parámetros sospechosos de un log de texto plano
    (heurística sobre la URL cruda, sin parseo XML/JSON)."""
    patron = re.compile(r"[?&](\w*(_id|Id|ID|user|account|uid|pid))=\d+")
    sospechosos = set()
    with open(path, "r", errors="ignore") as f:
        for linea in f:
            for match in patron.findall(linea):
                sospechosos.add(match[0])
    if not silent:
        print(f"[+] Parámetros IDOR sospechosos encontrados: {sorted(sospechosos)}")
    return list(sospechosos)


def _param_sospechoso(param):
    return bool(CONFIG.idor_param_regex.search(param))


def extraer_endpoints_burp_xml(xml_path, silent=False):
    endpoints = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for item in root.iter("item"):
            url = item.findtext("url")
            if not url:
                continue
            qs = parse_qs(urlparse(url).query)
            for param in qs:
                if _param_sospechoso(param):
                    endpoints.append((url, param))
    except ET.ParseError as e:
        print(f"[!] XML de Burp mal formado en {xml_path}: {e}")
    except Exception as e:
        print(f"[!] Error analizando XML de Burp: {e}")
    if not silent:
        print(f"[+] Endpoints/parámetros encontrados (XML): {len(endpoints)}")
    return endpoints


def parse_burp_json(json_path, silent=False):
    endpoints = []
    try:
        with open(json_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[!] JSON de Burp inválido en {json_path} (línea {e.lineno}, "
              f"columna {e.colno}): {e.msg}")
        return endpoints
    except Exception as e:
        print(f"[!] Error leyendo {json_path}: {e}")
        return endpoints

    # Soporta tanto {"items": [...]} (formato item-wrapper) como una lista
    # plana [...] (formato de ejemplo simplificado usado en examples/).
    items = data.get("items", data) if isinstance(data, dict) else data
    for item in items:
        url = item.get("url")
        params_inline = item.get("params")
        if url:
            qs = parse_qs(urlparse(url).query)
            for param in qs:
                if _param_sospechoso(param):
                    endpoints.append((url, param))
        elif url is None and params_inline and item.get("host") and item.get("path"):
            # Formato de ejemplo: host + path + params[] en vez de url completa
            base = f"https://{item['host']}{item['path'].split('?')[0]}"
            for p in params_inline:
                if _param_sospechoso(p.get("name", "")):
                    endpoints.append((base + f"?{p['name']}={p.get('value','')}", p["name"]))
    if not silent:
        print(f"[+] Endpoints/parámetros encontrados (JSON): {len(endpoints)}")
    return endpoints
