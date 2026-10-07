import importlib.util
import json
from pathlib import Path
from unittest.mock import Mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "build.py"
spec = importlib.util.spec_from_file_location("build", MODULE_PATH)
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


def test_build_uses_configured_app_identity_and_version(tmp_path, monkeypatch):
    (tmp_path / "globalConfig.json").write_text(
        json.dumps({"meta": {"name": "TA_test", "version": "1.2.3"}})
    )
    cache = tmp_path / "output" / "TA_test" / "bin" / "__pycache__"
    cache.mkdir(parents=True)
    (cache / "old.pyc").write_bytes(b"cached")
    run = Mock()
    monkeypatch.setattr(build, "ROOT", tmp_path)
    monkeypatch.setattr(build.subprocess, "run", run)

    build.main()

    commands = [call.args[0] for call in run.call_args_list]
    generator = next(command for command in commands if "--ta-version" in command)
    assert generator[generator.index("--ta-version") + 1] == "1.2.3"
    assert commands[-1][-2:] == ["--path", "output/TA_test"]
    assert all(
        call.kwargs == {"cwd": tmp_path, "check": True} for call in run.call_args_list
    )
    assert not cache.exists()
