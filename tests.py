#intended with pytest
import csv
import json
import os
import runpy
import sys
import pytest
import sbom

SBOM_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sbom.py")


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
        runpy.run_path(SBOM_SCRIPT, run_name="__main__")
    assert exc.value.code == 1


def run_cli(*args):
    return sbom.run([str(a) for a in args])


def test_writes_csv_and_json(tmp_path, capsys):
    make_repo(tmp_path, "a", requirements="requests==2.31.0\n")
    make_repo(
        tmp_path,
        "b",
        package_json={
            "dependencies": {"react": "^18.2.0"},
            "devDependencies": {"jest": "29.7.0"},
        },
    )
    assert run_cli(tmp_path) == 0

    out = capsys.readouterr().out
    assert f"Found 2 repositories in '{tmp_path}'" in out
    assert f"Saved SBOM in CSV format to '{tmp_path / 'sbom.csv'}'" in out
    assert f"Saved SBOM in JSON format to '{tmp_path / 'sbom.json'}'" in out

    with open(tmp_path / "sbom.csv", newline="") as f:
        rows = list(csv.DictReader(f))
    assert [(r["name"], r["version"], r["type"], r["scope"]) for r in rows] == [
        ("requests", "2.31.0", "pip", "runtime"),
        ("react", "^18.2.0", "npm", "runtime"),
        ("jest", "29.7.0", "npm", "dev"),
    ]
    assert rows[0]["path"] == str(tmp_path / "a" / "requirements.txt")
    assert rows[0]["repository"] == "a"

    data = json.loads((tmp_path / "sbom.json").read_text())
    assert data["dependencies"] == rows
    assert [r["name"] for r in data["repositories"]] == ["a", "b"]


def test_ignores_directories_that_are_not_repos(tmp_path):
    make_repo(tmp_path, "repo", requirements="flask\n")
    (tmp_path / "not_a_repo").mkdir()
    (tmp_path / "not_a_repo" / "requirements.txt").write_text("django\n")
    assert [d["name"] for d in sbom.scan(tmp_path)] == ["flask"]


def test_repo_without_dependency_files_is_skipped(tmp_path, capsys):
    make_repo(tmp_path, "empty")
    make_repo(tmp_path, "app", requirements="flask\n")
    assert run_cli(tmp_path) == 0
    assert "no requirements.txt or package.json" in capsys.readouterr().err
    data = json.loads((tmp_path / "sbom.json").read_text())
    assert [r["name"] for r in data["repositories"]] == ["app"]


def test_invalid_package_json_is_reported(tmp_path, capsys):
    bad = make_repo(tmp_path, "bad")
    (bad / "package.json").write_text("{not json")
    make_repo(tmp_path, "good", requirements="flask\n")
    assert run_cli(tmp_path) == 1
    assert "not valid JSON" in capsys.readouterr().err
    with open(tmp_path / "sbom.csv", newline="") as f:
        assert [r["name"] for r in csv.DictReader(f)] == ["flask"]


def test_no_repositories(tmp_path, capsys):
    assert run_cli(tmp_path) == 1
    assert "no git repositories found" in capsys.readouterr().err
    assert not (tmp_path / "sbom.csv").exists()


def test_path_is_a_file(tmp_path, capsys):
    f = tmp_path / "file.txt"
    f.write_text("")
    assert run_cli(f) == 1
    assert "is not a directory" in capsys.readouterr().err


def test_wrong_number_of_arguments(tmp_path):
    assert run_cli() == 2
    assert run_cli(tmp_path, tmp_path) == 2


def test_help(capsys):
    assert run_cli("--help") == 0
    assert "usage" in capsys.readouterr().out


COMMIT = "a" * 40


def test_commit_from_loose_ref(tmp_path):
    repo = make_repo(tmp_path, "r", requirements="flask\n")
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (repo / ".git" / "refs" / "heads").mkdir(parents=True)
    (repo / ".git" / "refs" / "heads" / "main").write_text(COMMIT + "\n")
    assert sbom.git_commit(repo) == COMMIT
    assert sbom.scan(tmp_path)[0]["commit"] == COMMIT


def test_commit_from_packed_refs(tmp_path):
    repo = make_repo(tmp_path, "r")
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (repo / ".git" / "packed-refs").write_text(
        f"# pack-refs with: peeled fully-peeled sorted\n{COMMIT} refs/heads/main\n"
    )
    assert sbom.git_commit(repo) == COMMIT


def test_commit_detached_head(tmp_path):
    repo = make_repo(tmp_path, "r")
    (repo / ".git" / "HEAD").write_text(COMMIT + "\n")
    assert sbom.git_commit(repo) == COMMIT


def test_commit_from_gitdir_file(tmp_path):
    real = tmp_path / "real_git_dir"
    real.mkdir()
    (real / "HEAD").write_text(COMMIT + "\n")
    repo = tmp_path / "repos" / "r"
    repo.mkdir(parents=True)
    (repo / ".git").write_text("gitdir: ../../real_git_dir\n")
    assert sbom.git_commit(repo) == COMMIT


def test_commit_missing(tmp_path):
    repo = make_repo(tmp_path, "r")
    assert sbom.git_commit(repo) == ""


def test_csv_escapes_formulas(tmp_path):
    make_repo(tmp_path, "a", requirements="foo==1.*\nbar==2.0\n")
    make_repo(
        tmp_path,
        "b",
        package_json={"dependencies": {'=HYPERLINK("http://x")': "1.0.0", "baz": "=1.0.0"}},
    )
    assert run_cli(tmp_path) == 0

    with open(tmp_path / "sbom.csv", newline="") as f:
        rows = list(csv.DictReader(f))
    assert [(r["name"], r["version"]) for r in rows] == [
        ("foo", "'==1.*"),
        ("bar", "2.0"),
        ("'=HYPERLINK(\"http://x\")", "1.0.0"),
        ("baz", "'=1.0.0"),
    ]

    data = json.loads((tmp_path / "sbom.json").read_text())
    assert [(d["name"], d["version"]) for d in data["dependencies"]] == [
        ("foo", "==1.*"),
        ("bar", "2.0"),
        ('=HYPERLINK("http://x")', "1.0.0"),
        ("baz", "=1.0.0"),
    ]


@pytest.mark.parametrize(
    "value",
    [
        "=1+1",
        "+1",
        "-1",
        "@SUM(A1)",
        "\t=1",
        "\r=1",
        "@scope/name(1)",
        "@scope/a|cmd",
        "@Scope/Name",
        "@scope",
        "@babel/core\n=1",
    ],
)
def test_csv_safe_prefixes_formulas(value):
    assert sbom._csv_safe(value) == "'" + value


@pytest.mark.parametrize(
    "value",
    [
        "requests",
        "2.31.0",
        "^18.2.0",
        ">=2.0",
        "",
        "a=b",
        "@babel/core",
        "@emotion/react",
        "@types/node",
        "@mui/x-date-pickers",
    ],
)
def test_csv_safe_keeps_normal_values(value):
    assert sbom._csv_safe(value) == value


def test_csv_keeps_scoped_npm_names(tmp_path):
    make_repo(
        tmp_path,
        "gui",
        package_json={
            "dependencies": {"@emotion/react": "11.13.0"},
            "devDependencies": {"@babel/core": "7.25.2"},
        },
    )
    assert run_cli(tmp_path) == 0
    with open(tmp_path / "sbom.csv", newline="") as f:
        assert [r["name"] for r in csv.DictReader(f)] == ["@emotion/react", "@babel/core"]
