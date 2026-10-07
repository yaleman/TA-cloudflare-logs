"""Write the built package identity to GitHub Actions step outputs."""

import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    meta = json.loads((ROOT / "globalConfig.json").read_text(encoding="utf-8"))["meta"]
    archive = Path(f"{meta['name']}-{meta['version']}.tar.gz")
    if not (ROOT / archive).is_file():
        raise SystemExit(f"Package not found: {archive}")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"tag=v{meta['version']}\n")
        output.write(f"archive={archive}\n")


if __name__ == "__main__":
    main()
