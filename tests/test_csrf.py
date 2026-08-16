import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.csrf import detectar_csrf, generar_poc_html


def test_detecta_csrf_sin_token_con_cookie():
    veredicto = detectar_csrf(
        "POST",
        {"Cookie": "session=abc123"},
        body={"amount": "1000"},
        url="https://target-site.com/api/transfer",
    )
    assert veredicto["sospechoso"] is True
    assert veredicto["ruta_sensible"] is True


def test_no_sospechoso_con_token_csrf():
    veredicto = detectar_csrf(
        "POST",
        {"Cookie": "session=abc123"},
        body={"amount": "1000", "csrf_token": "xyz"},
        url="https://target-site.com/api/transfer",
    )
    assert veredicto["sospechoso"] is False


def test_no_sospechoso_con_bearer_jwt():
    veredicto = detectar_csrf(
        "POST",
        {"Cookie": "session=abc123", "Authorization": "Bearer eyJabc.def.ghi"},
        body={"amount": "1000"},
        url="https://target-site.com/api/transfer",
    )
    assert veredicto["sospechoso"] is False
    assert veredicto["usa_bearer_jwt"] is True


def test_get_no_es_sospechoso():
    veredicto = detectar_csrf("GET", {"Cookie": "session=abc"}, url="https://x.com/profile")
    assert veredicto["sospechoso"] is False


def test_generar_poc_html_contiene_campos():
    html = generar_poc_html("https://target-site.com/api/transfer", "POST",
                             {"amount": "1000", "to": "attacker"})
    assert 'name="amount" value="1000"' in html
    assert "target-site.com/api/transfer" in html
    assert "document.forms[0].submit()" in html
