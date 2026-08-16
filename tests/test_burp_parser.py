import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.burp_parser import parse_burp_json, extraer_endpoints_burp_xml


def test_parse_burp_json_ejemplo_valido(tmp_path):
    ejemplo = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "examples", "logs_burp_REAL.json",
    )
    endpoints = parse_burp_json(ejemplo, silent=True)
    assert len(endpoints) >= 2
    params = [p for _, p in endpoints]
    assert "user" in params
    assert "id" in params


def test_parse_burp_json_invalido_no_revienta(tmp_path):
    roto = tmp_path / "roto.json"
    roto.write_text('[{"host": "x", "path": "/a?id=1", "params": [{"name": "id", "value": "1"},]}]')
    # No debe lanzar excepción -- debe devolver lista vacía y avisar.
    endpoints = parse_burp_json(str(roto), silent=True)
    assert endpoints == []


def test_extraer_endpoints_xml_basico(tmp_path):
    xml = tmp_path / "burp.xml"
    xml.write_text("""<?xml version="1.0"?>
<items>
  <item>
    <url>https://target-site.com/profile?user_id=42</url>
  </item>
  <item>
    <url>https://target-site.com/static/logo.png</url>
  </item>
</items>
""")
    endpoints = extraer_endpoints_burp_xml(str(xml), silent=True)
    assert ("https://target-site.com/profile?user_id=42", "user_id") in endpoints
