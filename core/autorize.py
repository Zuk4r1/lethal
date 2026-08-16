"""
Modo Autorize -- compara respuesta autenticada vs. respuesta con un
token/usuario alternativo para detectar bypass de autorización (BOLA/IDOR
horizontal o vertical).

La v2.1 usaba `resp_auth.text.strip() == resp_alt.text.strip()`: igualdad
exacta de string. Cualquier timestamp, nonce o CSRF token en el body
rompía la comparación, generando falsos negativos justo en el caso más
crítico (bypass de autorización real). Ahora se usa similarity ratio
sobre texto normalizado -- ver core/detection.py.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.detection import autorize_veredicto, detectar_datos_sensibles, es_bloqueada
from core.http_client import ip_trust_probe_headers, RateLimiter
from core.evidence import guardar_evidencia
from core.idor import payload_variants, _build_url, obtener_baseline


def autorize_advanced(url, param_name, id_list, headers, alt_headers, method,
                       session, threads=10, timeout=10, capture_evidence=True,
                       silent=False, progress_cb=None, forbidden_signature=None):
    resultados = []
    limiter = RateLimiter()
    payloads = [p for id_ in id_list for p in payload_variants(id_)]

    # Baseline de denegación PARA LOS HEADERS ALTERNATIVOS -- necesario
    # para distinguir "el usuario alt obtuvo acceso real" de "el usuario
    # alt fue denegado, igual que siempre" (ver nota en autorize_veredicto).
    baseline_alt_resp = obtener_baseline(session, url, param_name, alt_headers, method, timeout)
    baseline_alt_text = baseline_alt_resp.text if baseline_alt_resp is not None else None

    def probar(payload):
        limiter.wait()
        objetivo = _build_url(url, param_name, payload)
        req_headers_auth = ip_trust_probe_headers(headers.copy() if headers else None)
        req_headers_alt = ip_trust_probe_headers(alt_headers.copy() if alt_headers else {})
        try:
            resp_auth = session.request(method=method, url=objetivo,
                                         headers=req_headers_auth, timeout=timeout)
            resp_alt = session.request(method=method, url=objetivo,
                                        headers=req_headers_alt, timeout=timeout)
            limiter.note_response(resp_alt.status_code)

            alt_bloqueada, _, _ = es_bloqueada(resp_alt, forbidden_signature, baseline_alt_text)
            bypass, ratio = autorize_veredicto(resp_auth.text, resp_alt.text, alt_bloqueada)
            sensibles = detectar_datos_sensibles(resp_alt.text) if bypass else []

            if bypass:
                desc = f"Bypass de autorización: {ratio*100:.1f}% similar a la respuesta autenticada original"
            elif alt_bloqueada:
                desc = "Usuario/token alternativo correctamente denegado (no vulnerable)"
            else:
                desc = f"Usuario alternativo obtuvo acceso pero con contenido distinto ({ratio*100:.1f}% similitud) -- revisar manualmente"

            resultado = {
                "id": payload,
                "status": resp_alt.status_code,
                "desc": desc + (f" [datos sensibles: {', '.join(sensibles)}]" if sensibles else ""),
                "vulnerable": bypass,
                "similitud": ratio,
            }
            if bypass and capture_evidence:
                ev_path = guardar_evidencia(
                    resultado,
                    {"method": method, "url": objetivo, "headers": req_headers_alt, "body": None},
                    {"status": resp_alt.status_code, "headers": dict(resp_alt.headers),
                     "body": resp_alt.text},
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
