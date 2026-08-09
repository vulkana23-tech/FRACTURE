import os

# spectre-ollama (Docker, ya corriendo con los modelos reales) publica
# en 127.0.0.1:11435 -- confirmado en vivo que hay OTRA instancia nativa
# de Ollama en el host escuchando en el puerto default 11434, pero SIN
# modelos descargados (server reachable, /api/tags vacio). Nunca usar el
# default 11434 aca, apunta al vacio.
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11435")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3-coder:30b")
