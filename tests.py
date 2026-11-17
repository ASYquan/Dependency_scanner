#intended with pytest
import json
import sys
import pytest
import sbom


def make_repo(root, name, requirements=None, package_json=None):
    repo = root / name
    (repo / ".git").mkdir(parents=True)
    if requirements is not None:
        (repo / "requirements.txt").write_text(requirements)
    if package_json is not None:
        (repo / "package.json").write_text(json.dumps(package_json))
    return repo


def test_parse_requirements_skips_comments(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("# comment\n\nrequests==2.31.0\nflask>=2.0  # web\n")
    deps = sbom.parse_requirements(f)
    assert [(d["name"], d["version"]) for d in deps] == [
        ("requests", "2.31.0"),
        ("flask", ">=2.0"),
    ]


def test_counts_pip_and_npm_deps(tmp_path):
    make_repo(tmp_path, "a", requirements="requests==2.31.0\nflask==3.0.0\n")
    make_repo(tmp_path, "b", package_json={"dependencies": {"react": "^18.2.0"}})
    deps = sbom.scan(tmp_path)
    assert len(deps) == 3
    assert {d["type"] for d in deps} == {"pip", "npm"}


def test_missing_directory_exits_nonzero(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["sbom.py", str(tmp_path / "nope")])
    with pytest.raises(SystemExit) as exc:
        sbom.main()
    assert exc.value.code != 0
