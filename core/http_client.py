"""
Cliente HTTP compartido.

Antes cada función hacía `requests.request(...)` suelto, sin reutilizar
conexión TCP/TLS (mucho más lento a escala) y sin reintentos ante errores
transitorios de red. Ahora se usa una única requests.Session con
HTTPAdapter + Retry (backoff exponencial en 429/502/503/504).

También reemplaza los headers "anti-WAF" originales (X-Forwarded-For,
X-Remote-IP con IPs 127.0.0.x aleatorias) que en realidad NO evaden WAFs
modernos -- eso solo tiene sentido como prueba específica de "IP-based
access control bypass" (CWE-290: Authorization Bypass Through User-
Controlled Key), no como evasión general de detección de bot. Se han
renombrado y documentado para reflejar lo que realmente prueban.
"""
import random
import threading
import time

import requests
from requests.adapters import HTTPAdapter
try:
    from urllib3.util.retry import Retry
except ImportError:  # urllib3 < 2
    from urllib3.util import Retry


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
    "Mozilla/5.0 (Android 11; Mobile; rv:89.0)",
]


def build_session(retries=3, backoff_factor=0.5, proxy=None):
    """Sesión con conexión persistente + reintentos automáticos con
    backoff exponencial ante 429/502/503/504."""
    session = requests.Session()
    retry_cfg = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 502, 503, 504],
        allowed_methods=None,  # reintenta también en POST/PUT/DELETE
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_cfg, pool_maxsize=50, pool_connections=50)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    return session


def random_user_agent():
    return random.choice(USER_AGENTS)


def ip_trust_probe_headers(headers=None):
    """
    Headers para probar 'IP-based access control bypass' (CWE-290) --
    útil SOLO si el target confía en headers de cliente para allowlisting
    de IP (proxy/WAF mal configurado que reenvía el header sin validar
    contra la IP TCP real). Esto NO evade un WAF moderno (Cloudflare, AWS
    WAF, Akamai) que hace rate-limiting sobre la IP TCP real -- es una
    prueba de un bug específico, no evasión general.
    """
    fake_ip = f"127.0.0.{random.randint(2, 254)}"
    probe = {
        "X-Forwarded-For": fake_ip,
        "X-Real-IP": fake_ip,
        "X-Client-IP": fake_ip,
        "X-Originating-IP": fake_ip,
        "User-Agent": random_user_agent(),
    }
    if headers:
        probe.update(headers)  # las del usuario tienen prioridad (ej. Authorization)
    return probe


class RateLimiter:
    """Backoff adaptativo simple y compartido entre threads: si el target
    empieza a devolver 429, todas las peticiones concurrentes bajan de
    ritmo hasta que se recupere, en vez de seguir martillando el endpoint."""

    def __init__(self, base_min=0.1, base_max=0.7):
        self.base_min = base_min
        self.base_max = base_max
        self._flag = threading.Event()
        self._lock = threading.Lock()
        self._hits = 0

    def note_response(self, status_code):
        if status_code == 429:
            with self._lock:
                self._hits += 1
            self._flag.set()

    def wait(self):
        if self._flag.is_set():
            with self._lock:
                penalty = min(self._hits * 1.5, 10)
            time.sleep(random.uniform(2, 4) + penalty)
        else:
            time.sleep(random.uniform(self.base_min, self.base_max))

    def maybe_recover(self):
        """Llamar periódicamente para permitir que el limiter se recupere
        si el target dejó de devolver 429."""
        with self._lock:
            if self._hits > 0:
                self._hits -= 1
            if self._hits <= 0:
                self._flag.clear()
