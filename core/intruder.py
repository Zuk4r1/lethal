"""Fuzzing genérico de un parámetro con lista de payloads personalizada,
versión concurrente (ver core/idor.py para el razonamiento del cambio)."""
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.detection import es_bloqueada
from core.http_client import ip_trust_probe_headers, RateLimiter
from core.idor import obtener_baseline, _build_url


def intruder(url, param_name, payloads, headers, method, session,
             forbidden_signature=None, threads=10, timeout=10, silent=False,
             progress_cb=None):
    baseline_resp = obtener_baseline(session, url, param_name, headers, method, timeout)
    baseline_text = baseline_resp.text if baseline_resp is not None else None

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
            return {
                "payload": payload,
                "status": resp.status_code,
                "desc": razon,
                "vulnerable": not bloqueada,
                "similitud": ratio,
            }
        except Exception as e:
            return {"payload": payload, "status": "ERROR", "desc": str(e), "vulnerable": False}

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(probar, p): p for p in payloads}
        done = 0
        for future in as_completed(futures):
            resultados.append(future.result())
            done += 1
            if progress_cb:
                progress_cb(done, len(payloads))
    return resultados
