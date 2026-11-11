import os
import subprocess
import sys
from pathlib import Path

ASKAR_REPO_URL = "https://github.com/Welhelha/askar.git"
ASKAR_REF = "1b20d4c752f41c7c96b5baee48fa317befb5dc43"

CACHE_DIR = Path(__file__).resolve().parent / ".cache"
ASKAR_ROOT = CACHE_DIR / "askar"
ASKAR_PYTHON_PATH = ASKAR_ROOT / "wrappers" / "python"
ASKAR_DEBUG_LIBRARY = ASKAR_ROOT / "target" / "debug"

CACHE_DIR.mkdir(exist_ok=True)

if not ASKAR_ROOT.exists():
    subprocess.run(["git", "clone", ASKAR_REPO_URL, str(ASKAR_ROOT)], check=True)

subprocess.run(["git", "-C", str(ASKAR_ROOT), "fetch", "origin"], check=True)
subprocess.run(["git", "-C", str(ASKAR_ROOT), "checkout", ASKAR_REF], check=True)

subprocess.run(
    [
        "cargo", "build",
        "--manifest-path", str(ASKAR_ROOT / "Cargo.toml"),
        "--lib", "--features", "mldsa",
    ],
    check=True,
)

os.environ["DYLD_LIBRARY_PATH"] = os.pathsep.join(
    filter(None, (str(ASKAR_DEBUG_LIBRARY), os.environ.get("DYLD_LIBRARY_PATH")))
)
sys.path.insert(0, str(ASKAR_PYTHON_PATH))

import aries_askar
print("aries_askar chargé depuis :", aries_askar.__file__)