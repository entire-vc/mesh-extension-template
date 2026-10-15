"""Verify the installed publisher CLI rejects a malformed copy of this checkout."""

import json
import shutil
import subprocess
import sys
from pathlib import Path


def test_invalid_manifest_version_is_rejected(tmp_path):
    root = Path(__file__).resolve().parents[1]
    broken = tmp_path / "broken"
    shutil.copytree(
        root, broken,
        ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", ".pytest_cache"),
    )
    manifest = broken / "mesh-extension.json"
    data = json.loads(manifest.read_text())
    data["version"] = "invalid"
    manifest.write_text(json.dumps(data))
    result = subprocess.run(
        [sys.executable, "-m", "mesh_ext", "validate", str(broken)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 1, (result.stdout, result.stderr)
    schema = json.loads(result.stdout)["checks"]["schema"]
    assert schema["status"] == "fail"
    assert "version:pattern" in schema["reasons"]
