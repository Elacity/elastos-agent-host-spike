import subprocess
import sys
from pathlib import Path

PACK = Path(__file__).resolve().parents[1]
if str(PACK) not in sys.path:
    sys.path.insert(0, str(PACK))


def init_repo(path: Path, *, text: str = "x\n") -> str:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init"], cwd=path, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "pack-test@example.test"],
        cwd=path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "pack-test"],
        cwd=path,
        check=True,
        capture_output=True,
    )
    (path / "README").write_text(text, encoding="utf-8")
    subprocess.run(["git", "add", "README"], cwd=path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "init"],
        cwd=path,
        check=True,
        capture_output=True,
    )
    sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=path, text=True
    ).strip()
    return sha


def write_owned_marker(path: Path) -> None:
    from pins import MARKER_TEXT, write_marker

    write_marker(path)
    assert (path / ".mac-evidence-pack-owned").read_text(encoding="utf-8") == MARKER_TEXT
