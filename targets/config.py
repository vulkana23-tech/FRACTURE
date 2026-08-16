import os

# Loader minimo de .env (sin agregar python-dotenv como dependencia
# nueva -- el resto del proyecto tampoco lo usa, todo lee de
# os.environ directo). Nunca pisa una variable ya seteada de verdad en
# el entorno (ej. por systemd Environment=) -- .env es solo un
# fallback para uso manual desde una shell interactiva.
_ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
if os.path.isfile(_ENV_PATH):
    with open(_ENV_PATH, "r", encoding="utf-8") as _fh:
        for _line in _fh:
            _line = _line.strip()
            if not _line or _line.startswith("#") or "=" not in _line:
                continue
            _key, _, _value = _line.partition("=")
            os.environ.setdefault(_key.strip(), _value.strip())

# SPECTRE corre su propio Postgres publicado SOLO en localhost (confirmado
# con `docker port spectre-postgres` -- 127.0.0.1:5432, nunca expuesto a
# la red externa). FRACTURE lee de ahi en modo SOLO LECTURA (nunca
# escribe en la base de SPECTRE) para reusar los programas de bug bounty
# ya trackeados, en vez de duplicar ese tracking desde cero.
SPECTRE_DATABASE_URL = os.getenv(
    "SPECTRE_DATABASE_URL",
    "postgresql://spectre:Spectre_DB_Pass_2025@localhost:5432/spectre",
)

# Fine-grained PAT de solo lectura publica -- sube el rate limit real
# de la API de GitHub de 60/hora (sin auth) a 5000/hora. Opcional: sin
# esto, select_targets.py/find_patch_directed_candidates.py siguen
# funcionando igual, solo mas lento/limitado. Nunca se loggea ni se
# imprime -- ver _github_api_headers() en select_targets.py.
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
