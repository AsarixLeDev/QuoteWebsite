from __future__ import annotations

from pathlib import Path

# Répertoires de base
BASE_DIR: Path = Path(__file__).resolve().parent
DATA_DIR: Path = BASE_DIR / "data"
UPLOAD_DIR: Path = DATA_DIR / "uploads"
DATA_PATH: Path = DATA_DIR / "data.json"

# Assure l'existence des dossiers
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
