"""
Tests del motor de detección -- la parte más crítica de la herramienta
para la calidad de los hallazgos (falsos positivos/negativos).
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.detection import similitud, normalizar, autorize_veredicto, es_bloqueada


class FakeResponse:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


def test_normalizar_quita_timestamps():
    texto = '{"user": "bob", "created_at": "2026-08-16T10:00:00Z"}'
    normalizado = normalizar(texto)
    assert "2026-08-16" not in normalizado
    assert "__VOL__" in normalizado


def test_normalizar_quita_csrf_token():
    texto = '{"csrf_token": "abc123XYZ", "data": "ok"}'
    normalizado = normalizar(texto)
    assert "abc123XYZ" not in normalizado


def test_similitud_identico_es_1():
    assert similitud("hola mundo", "hola mundo") == 1.0


def test_similitud_ignora_campos_volatiles():
    a = '{"user_id": 42, "nonce": "aaa111", "name": "bob"}'
    b = '{"user_id": 42, "nonce": "bbb222", "name": "bob"}'
    # Antes (igualdad exacta de string) esto habría dado un falso
    # negativo -- ahora, tras normalizar el nonce, deben ser casi idénticos.
    assert similitud(a, b) > 0.95


def test_similitud_contenido_realmente_distinto():
    a = '{"user_id": 42, "name": "bob", "balance": 100}'
    b = '{"user_id": 99, "name": "alice", "balance": 5000}'
    assert similitud(a, b) < 0.85


def test_autorize_veredicto_detecta_bypass_pese_a_nonce():
    resp_auth = '{"account": "1234", "balance": "500", "csrf": "xxxxx"}'
    resp_alt = '{"account": "1234", "balance": "500", "csrf": "yyyyy"}'
    bypass, ratio = autorize_veredicto(resp_auth, resp_alt, resp_alt_bloqueada=False)
    assert bypass is True
    assert ratio > 0.9


def test_autorize_veredicto_no_bypass_cuando_datos_distintos():
    resp_auth = '{"account": "1234", "balance": "500"}'
    resp_alt = '{"error": "acceso denegado"}'
    bypass, ratio = autorize_veredicto(resp_auth, resp_alt, resp_alt_bloqueada=True)
    assert bypass is False


def test_autorize_veredicto_no_bypass_si_ambas_denegadas_igual():
    # Caso encontrado durante pruebas end-to-end de la v3.0: dos
    # denegaciones idénticas ("403 no autorizado" en ambos) tienen
    # ~100% de similitud pero NO son un bypass -- son una denegación
    # consistente. resp_alt_bloqueada=True debe anular el ratio alto.
    resp_auth = '{"error": "no autorizado", "csrf": "aaa"}'
    resp_alt = '{"error": "no autorizado", "csrf": "bbb"}'
    bypass, ratio = autorize_veredicto(resp_auth, resp_alt, resp_alt_bloqueada=True)
    assert ratio > 0.9  # el ratio en sí es alto...
    assert bypass is False  # ...pero no cuenta como bypass porque alt fue denegado


def test_es_bloqueada_por_status_http():
    resp = FakeResponse(403, "Forbidden")
    bloqueada, razon, ratio = es_bloqueada(resp)
    assert bloqueada is True
    assert "403" in razon


def test_es_bloqueada_por_similitud_con_baseline():
    baseline = '{"error": "no autorizado", "code": 1}'
    resp = FakeResponse(200, '{"error": "no autorizado", "code": 2}')
    bloqueada, razon, ratio = es_bloqueada(resp, baseline_text=baseline)
    assert bloqueada is True


def test_es_bloqueada_false_cuando_contenido_es_distinto():
    baseline = '{"error": "no autorizado"}'
    resp = FakeResponse(200, '{"user": "bob", "ssn": "123-45-6789", "balance": 9000}')
    bloqueada, razon, ratio = es_bloqueada(resp, baseline_text=baseline)
    assert bloqueada is False
