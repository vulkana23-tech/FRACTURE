import os

# SPECTRE corre su propio Postgres publicado SOLO en localhost (confirmado
# con `docker port spectre-postgres` -- 127.0.0.1:5432, nunca expuesto a
# la red externa). FRACTURE lee de ahi en modo SOLO LECTURA (nunca
# escribe en la base de SPECTRE) para reusar los programas de bug bounty
# ya trackeados, en vez de duplicar ese tracking desde cero.
SPECTRE_DATABASE_URL = os.getenv(
    "SPECTRE_DATABASE_URL",
    "postgresql://spectre:Spectre_DB_Pass_2025@localhost:5432/spectre",
)
