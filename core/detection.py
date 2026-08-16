"""
Motor de detección de "¿esta respuesta es distinta de un acceso denegado?".

Reemplaza dos heurísticas frágiles de la v2.1:
  1. `diff de longitud < 20 caracteres` para decidir bloqueo -> generaba
     falsos negativos con JSON de longitud variable y falsos positivos con
     objetos distintos de igual longitud.
  2. `resp_auth.text.strip() == resp_alt.text.strip()` en modo Autorize ->
     cualquier timestamp/nonce/CSRF token en el body rompía la comparación
     y escondía bypasses de autorización reales.

Ahora se usa difflib.SequenceMatcher sobre texto normalizado (campos
volátiles como timestamps/tokens sustituidos por un placeholder), con un
umbral de similitud configurable en config/patterns.yaml.
"""
import difflib
import re

from core.config import CONFIG


def normalizar(texto: str) -> str:
    """Sustituye campos volátiles conocidos (timestamps, tokens, nonces)
    por un placeholder fijo, para que no contaminen la comparación de
    similitud entre dos respuestas."""
    if not texto:
        return ""
    for patron in CONFIG.volatile_field_patterns:
        texto = patron.sub("__VOL__", texto)
    return texto


def similitud(a: str, b: str) -> float:
    """Ratio 0-1 de similitud entre dos textos, ya normalizados."""
    return difflib.SequenceMatcher(None, normalizar(a), normalizar(b)).ratio()


def detectar_datos_sensibles(texto: str):
    """Devuelve la lista de nombres de patrones de datos sensibles que
    matchean en el texto (jwt, aws_key, password_field, ...)."""
    if not texto:
        return []
    encontrados = []
    for patron in CONFIG.sensitive_data_patterns:
        if patron.search(texto):
            encontrados.append(patron.pattern[:30])
    return encontrados


def es_bloqueada(resp, forbidden_signature=None, baseline_text=None,
                  threshold=None):
    """
    Decide si una respuesta HTTP representa un acceso bloqueado/denegado.

    Sustituye la vieja `es_bloqueada()` de lethal.py v2.1. Devuelve
    (bloqueada: bool, razon: str, ratio_similitud: float|None).

    Orden de señales, de más a menos confiable:
      1. Status HTTP explícito de bloqueo (401/403/429).
      2. Firma de texto de "prohibido" configurada por el usuario (--forbidden).
      3. Similitud de contenido contra el baseline de acceso denegado
         (reemplaza el viejo `diff de longitud < 20`).
      4. Respuesta vacía.
      5. Patrón genérico de error en el texto (heurística de último recurso,
         menos confiable -- puede dar falsos positivos si el "error" forma
         parte de datos legítimos, ej. un ticket de soporte que contiene la
         palabra "denied").
    """
    threshold = threshold if threshold is not None else CONFIG.similarity_threshold

    if resp.status_code in (401, 403, 429):
        return True, f"HTTP {resp.status_code}", None

    if forbidden_signature and forbidden_signature.lower() in resp.text.lower():
        return True, "Firma de texto prohibido detectada", None

    ratio = None
    if baseline_text:
        ratio = similitud(resp.text, baseline_text)
        if ratio >= threshold:
            return True, f"Contenido {ratio*100:.1f}% similar al baseline de acceso denegado", ratio

    if not resp.text.strip():
        return True, "Respuesta vacía", ratio

    if re.search(r"(error|denied|forbidden|not authorized|no autorizado|acceso denegado)",
                 resp.text, re.I):
        return True, "Patrón de error genérico detectado (heurística débil, revisar manualmente)", ratio

    return False, "Respuesta distinta del baseline de acceso denegado", ratio


def autorize_veredicto(resp_auth_text, resp_alt_text, resp_alt_bloqueada,
                        threshold=None):
    """
    Compara la respuesta del usuario autenticado original contra la del
    usuario/token alternativo.

    IMPORTANTE: la similitud por sí sola NO basta. Si ambas respuestas
    están igualmente bloqueadas (ej. las dos devuelven "403 no
    autorizado"), la similitud es ~100% pero eso es una denegación
    consistente, no un bypass -- un bug real detectado durante las
    pruebas de esta v3.0: sin este chequeo, cada denegación idéntica se
    reportaba como falso positivo de bypass. Solo se considera bypass
    cuando la respuesta alternativa NO está bloqueada (obtuvo contenido
    real) Y ese contenido es similar al de la sesión autenticada original.

    Devuelve (bypass_detectado: bool, ratio: float).
    """
    threshold = threshold if threshold is not None else CONFIG.similarity_threshold
    ratio = similitud(resp_auth_text, resp_alt_text)
    if resp_alt_bloqueada:
        return False, ratio
    return ratio >= threshold, ratio
