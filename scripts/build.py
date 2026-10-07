"""Build portable Python dependencies, generate UCC output, and package the add-on."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    meta = json.loads((ROOT / "globalConfig.json").read_text(encoding="utf-8"))["meta"]
    app_directory = "output/" + meta["name"]
    wheels = ROOT / "build-wheels"
    wheels.mkdir(exist_ok=True)
    commands = [
        [
            "uv",
            "export",
            "--locked",
            "--no-dev",
            "--no-hashes",
            "--no-emit-project",
            "--output-file",
            "package/lib/requirements.txt",
        ],
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--wheel-dir",
            str(wheels),
            "splunk-sdk==2.1.1",
        ],
        [
            sys.executable,
            "-m",
            "splunk_add_on_ucc_framework",
            "build",
            "--source",
            "package",
            "--ta-version",
            meta["version"],
            "--overwrite",
            "--python-binary-name",
            sys.executable,
            "--pip-custom-flag",
            "--no-compile --ignore-installed --only-binary=:all: --platform any --python-version 3.9 --implementation py --abi none --find-links build-wheels",
        ],
        [
            sys.executable,
            "-m",
            "splunk_add_on_ucc_framework",
            "package",
            "--path",
            app_directory,
        ],
    ]
    for command in commands:
        if command[-2:] == ["--path", app_directory]:
            for cache in (ROOT / app_directory).rglob("__pycache__"):
                shutil.rmtree(cache)
        subprocess.run(command, cwd=ROOT, check=True)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode)
