"""
Carga de configuración externa (config/patterns.yaml).

Antes estos patrones estaban hardcodeados y duplicados entre lethal.py y
core/analyzer.py. Ahora viven en un único YAML editable sin tocar código
(mejora #7 de la auditoría).
"""
import os
import re
import yaml

_DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config", "patterns.yaml"
)

_DEFAULTS = {
    "idor_param_keywords": ["id", "user", "userid", "account", "uid", "token"],
    "csrf_token_names": ["csrf-token", "x-csrf-token", "csrfmiddlewaretoken", "authenticity_token"],
    "csrf_sensitive_path_keywords": ["delete", "update", "password", "admin", "transfer"],
    "sensitive_data_patterns": [
        {"name": "jwt", "regex": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9._-]{10,}\.[a-zA-Z0-9._-]{10,}"},
    ],
    "volatile_field_patterns": [
        r'"?(csrf|xsrf|token|nonce)"?\s*[:=]\s*"?[\w\-\.]+"?',
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?',
    ],
    "similarity_threshold": 0.92,
}


class Config:
    def __init__(self, path=None):
        path = path or _DEFAULT_PATH
        data = dict(_DEFAULTS)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f) or {}
                data.update(loaded)
            except Exception as e:
                # Config rota no debe tumbar la herramienta -- se avisa y se
                # sigue con defaults seguros.
                print(f"[!] No se pudo cargar {path} ({e}); usando patrones por defecto.")
        self._raw = data

        self.idor_param_keywords = data["idor_param_keywords"]
        self.csrf_token_names = data["csrf_token_names"]
        self.csrf_sensitive_path_keywords = data["csrf_sensitive_path_keywords"]
        self.similarity_threshold = float(data["similarity_threshold"])

        self.sensitive_data_patterns = [
            re.compile(p["regex"]) for p in data["sensitive_data_patterns"]
        ]
        self.volatile_field_patterns = [
            re.compile(p) for p in data["volatile_field_patterns"]
        ]

        self.idor_param_regex = re.compile(
            r"(" + "|".join(re.escape(k) for k in self.idor_param_keywords) + r")(_?id|Id|ID)?$",
            re.IGNORECASE,
        )


# Instancia compartida por defecto -- los módulos que solo necesitan la
# config estándar pueden hacer `from core.config import CONFIG`.
CONFIG = Config()
