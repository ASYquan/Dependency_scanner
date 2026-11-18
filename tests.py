#intended with pytest
import csv
import json
import os
import re
import runpy
import sys

import pytest

import dependency_reader
import sbom

SBOM_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sbom.py")
COMMIT = "a" * 40


# --- helpers ----------------------------------------------------------------


def make_repo(root, name, requirements=None, package_json=None):
    repo = root / name
    (repo / ".git").mkdir(parents=True)
    if requirements is not None:
        (repo / "requirements.txt").write_text(requirements)
    if package_json is not None:
        (repo / "package.json").write_text(json.dumps(package_json))
    return repo


def run_cli(*args):
    return sbom.run([str(a) for a in args])


def read_csv(root):
    with open(root / "sbom.csv", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def read_json(root):
    return json.loads((root / "sbom.json").read_text(encoding="utf-8"))


def parse_line(line):
    return dependency_reader._parse_requirement_line(line)


# --- requirements.txt -------------------------------------------------------


def test_parse_requirements_skips_comments(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("# comment\n\nrequests==2.31.0\nflask>=2.0  # web\n")
    deps = sbom.parse_requirements(f)
    assert [(d["name"], d["version"]) for d in deps] == [
        ("requests", "2.31.0"),
        ("flask", ">=2.0"),
    ]


@pytest.mark.parametrize(
    "line, expected",
    [
        ("requests==2.31.0", ("requests", "==2.31.0")),
        ("requests", ("requests", "")),
        ("requests >= 2.0 , < 3", ("requests", ">=2.0,<3")),
        ("pkg~=1.4", ("pkg", "~=1.4")),
        ("pkg===1.0", ("pkg", "===1.0")),
        ("pkg!=1.5", ("pkg", "!=1.5")),
        ("pkg (>=1.0)", ("pkg", ">=1.0")),
        ("Django_Rest.Framework==3.0", ("Django_Rest.Framework", "==3.0")),
        ("requests[socks,security]==2.31.0", ("requests", "==2.31.0")),
        ('pywin32==306; sys_platform == "win32"', ("pywin32", "==306")),
        ("pkg==1.0 --hash=sha256:abc", ("pkg", "==1.0")),
        ("pkg==1.0\t--hash=sha256:abc", ("pkg", "==1.0")),
        ("pkg @ https://example.com/pkg-1.0.tar.gz", ("pkg", "https://example.com/pkg-1.0.tar.gz")),
        ("pkg==1.0  # pinned for reasons", ("pkg", "==1.0")),
    ],
)
def test_parse_requirement_line(line, expected):
    assert parse_line(line) == expected


@pytest.mark.parametrize(
    "line",
    [
        "",
        "   ",
        "# just a comment",
        "-r other.txt",
        "-c constraints.txt",
        "-e .",
        "-e git+https://github.com/a/b.git#egg=b",
        "--index-url https://example.com/simple",
        "git+https://github.com/a/b.git",
        "https://example.com/pkg.tar.gz",
        "./local/pkg",
        "pkg-1.0-py3-none-any.whl",
        "pkg[unclosed==1.0",
        "_private==1.0",
    ],
)
def test_parse_requirement_line_skips_non_requirements(line):
    assert parse_line(line) is None


def test_requirements_line_continuation(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("pkg==1.0 \\\n    --hash=sha256:abc \\\n    --hash=sha256:def\nflask\n")
    deps = sbom.parse_requirements(f)
    assert [(d["name"], d["version"]) for d in deps] == [("pkg", "1.0"), ("flask", "")]


def test_requirements_windows_line_endings_and_bom(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_bytes(b"\xef\xbb\xbfrequests==2.31.0\r\nflask\r\n")
    assert [d["name"] for d in sbom.parse_requirements(f)] == ["requests", "flask"]


def test_requirements_not_utf8(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_bytes(b"requests==2.31.0\n\xff\xfe\n")
    with pytest.raises(sbom.DependencyFileError, match="not valid UTF-8"):
        sbom.parse_requirements(f)


@pytest.mark.parametrize(
    "spec, version",
    [
        ("==2.31.0", "2.31.0"),
        (">=2.0", ">=2.0"),
        ("==1.*", "==1.*"),
        ("===1.0", "===1.0"),
        ("==1.0,!=1.0.1", "==1.0,!=1.0.1"),
        ("", ""),
    ],
)
def test_pip_version(spec, version):
    assert dependency_reader._pip_version(spec) == version


@pytest.mark.parametrize(
    "name, spec, purl",
    [
        ("requests", "==2.31.0", "pkg:pypi/requests@2.31.0"),
        ("requests", ">=2.0", "pkg:pypi/requests"),
        ("Django_Rest.Framework", "==3.0", "pkg:pypi/django-rest-framework@3.0"),
        ("a__b--c..d", "", "pkg:pypi/a-b-c-d"),
        ("pkg", "==1.0+local", "pkg:pypi/pkg@1.0%2Blocal"),
    ],
)
def test_pypi_purl(name, spec, purl):
    assert dependency_reader._pypi_purl(name, spec) == purl


# --- package.json -----------------------------------------------------------


def write_package_json(tmp_path, content):
    f = tmp_path / "package.json"
    if isinstance(content, bytes):
        f.write_bytes(content)
    else:
        f.write_text(content if isinstance(content, str) else json.dumps(content))
    return f


def test_package_json_sections_and_scopes(tmp_path):
    f = write_package_json(
        tmp_path,
        {
            "name": "app",
            "dependencies": {"react": "^18.2.0"},
            "devDependencies": {"jest": "29.7.0", "react": "18.2.0"},
            "optionalDependencies": {"fsevents": "2.3.3"},
            "peerDependencies": {"react-dom": ">=18"},
            "bundledDependencies": ["ignored"],
        },
    )
    deps = sbom.parse_package_json(f)
    assert [(d["name"], d["version"], d["scope"]) for d in deps] == [
        ("react", "^18.2.0", "runtime"),
        ("jest", "29.7.0", "dev"),
        ("react", "18.2.0", "dev"),
        ("fsevents", "2.3.3", "optional"),
        ("react-dom", ">=18", "peer"),
    ]


def test_package_json_without_dependencies(tmp_path):
    f = write_package_json(tmp_path, {"name": "app", "dependencies": ["not", "a", "dict"]})
    assert sbom.parse_package_json(f) == []


def test_package_json_non_string_versions(tmp_path):
    f = write_package_json(tmp_path, {"dependencies": {"a": None, "b": 5, "c": {"x": 1}}})
    deps = sbom.parse_package_json(f)
    assert [(d["name"], d["version"]) for d in deps] == [
        ("a", "null"),
        ("b", "5"),
        ("c", '{"x": 1}'),
    ]


def test_package_json_with_bom(tmp_path):
    f = write_package_json(tmp_path, b'\xef\xbb\xbf{"dependencies": {"react": "18.2.0"}}')
    assert [d["name"] for d in sbom.parse_package_json(f)] == ["react"]


@pytest.mark.parametrize(
    "content, message",
    [
        ("{not json", "not valid JSON"),
        ("", "not valid JSON"),
        ("[1, 2]", "does not contain a JSON object"),
        ('"text"', "does not contain a JSON object"),
        ("[" * 100_000, "not valid JSON"),
        (b"\xff\xfe{}", "not valid UTF-8"),
    ],
)
def test_invalid_package_json(tmp_path, content, message):
    f = write_package_json(tmp_path, content)
    with pytest.raises(sbom.DependencyFileError, match=message):
        sbom.parse_package_json(f)


@pytest.mark.parametrize(
    "name, spec, purl",
    [
        ("react", "18.2.0", "pkg:npm/react@18.2.0"),
        ("react", "^18.2.0", "pkg:npm/react"),
        ("react", "=18.2.0", "pkg:npm/react@18.2.0"),
        ("react", "v18.2.0", "pkg:npm/react@18.2.0"),
        ("react", "18.2.0-beta.1", "pkg:npm/react@18.2.0-beta.1"),
        ("react", "18.2.0+build", "pkg:npm/react@18.2.0%2Bbuild"),
        ("react", "1.2.3 - 2.0.0", "pkg:npm/react"),
        ("react", "1.2.3 || 2.0.0", "pkg:npm/react"),
        ("react", "latest", "pkg:npm/react"),
        ("react", "\u00b2.1.1", "pkg:npm/react"),
        ("@mui/material", "5.0.0", "pkg:npm/%40mui/material@5.0.0"),
    ],
)
def test_npm_purl(name, spec, purl):
    assert dependency_reader._npm_purl(name, spec) == purl


# --- finding repositories ---------------------------------------------------


def test_counts_pip_and_npm_deps(tmp_path):
    make_repo(tmp_path, "a", requirements="requests==2.31.0\nflask==3.0.0\n")
    make_repo(tmp_path, "b", package_json={"dependencies": {"react": "^18.2.0"}})
    deps = sbom.scan(tmp_path)
    assert len(deps) == 3
    assert {d["type"] for d in deps} == {"pip", "npm"}


def test_ignores_directories_that_are_not_repos(tmp_path):
    make_repo(tmp_path, "repo", requirements="flask\n")
    (tmp_path / "not_a_repo").mkdir()
    (tmp_path / "not_a_repo" / "requirements.txt").write_text("django\n")
    assert [d["name"] for d in sbom.scan(tmp_path)] == ["flask"]


def test_repos_are_sorted_and_not_nested(tmp_path):
    for name in ("c", "a", "b"):
        make_repo(tmp_path, name, requirements=f"{name}pkg\n")
    make_repo(tmp_path / "a", "nested", requirements="hidden\n")
    assert [os.path.basename(r) for r in sbom.find_repos(tmp_path)] == ["a", "b", "c"]
    assert "hidden" not in [d["name"] for d in sbom.scan(tmp_path)]


def test_git_file_counts_as_repo(tmp_path):
    repo = tmp_path / "worktree"
    repo.mkdir()
    (repo / ".git").write_text("gitdir: /somewhere/else\n")
    assert sbom.find_repos(tmp_path) == [str(repo)]


def test_dependency_file_must_be_a_file(tmp_path):
    repo = make_repo(tmp_path, "r")
    (repo / "requirements.txt").mkdir()
    assert sbom.scan(tmp_path) == []


# --- the git commit ---------------------------------------------------------


def write_git(repo, files):
    for name, content in files.items():
        path = repo / ".git" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)


def test_commit_from_loose_ref(tmp_path):
    repo = make_repo(tmp_path, "r", requirements="flask\n")
    write_git(repo, {"HEAD": "ref: refs/heads/main\n", "refs/heads/main": COMMIT + "\n"})
    assert sbom.git_commit(repo) == COMMIT
    assert sbom.scan(tmp_path)[0]["commit"] == COMMIT


def test_commit_from_packed_refs(tmp_path):
    repo = make_repo(tmp_path, "r")
    write_git(
        repo,
        {
            "HEAD": "ref: refs/heads/main\n",
            "packed-refs": (
                "# pack-refs with: peeled fully-peeled sorted\n"
                f"{'b' * 40} refs/heads/other\n"
                f"{COMMIT} refs/heads/main\n"
                f"^{'c' * 40}\n"
            ),
        },
    )
    assert sbom.git_commit(repo) == COMMIT


def test_loose_ref_wins_over_packed_ref(tmp_path):
    repo = make_repo(tmp_path, "r")
    write_git(
        repo,
        {
            "HEAD": "ref: refs/heads/main\n",
            "refs/heads/main": COMMIT + "\n",
            "packed-refs": f"{'b' * 40} refs/heads/main\n",
        },
    )
    assert sbom.git_commit(repo) == COMMIT


def test_commit_detached_head(tmp_path):
    repo = make_repo(tmp_path, "r")
    write_git(repo, {"HEAD": COMMIT + "\n"})
    assert sbom.git_commit(repo) == COMMIT


def test_commit_sha256_repository(tmp_path):
    repo = make_repo(tmp_path, "r")
    write_git(repo, {"HEAD": "f" * 64 + "\n"})
    assert sbom.git_commit(repo) == "f" * 64


def test_commit_from_gitdir_file(tmp_path):
    real = tmp_path / "real_git_dir"
    real.mkdir()
    (real / "HEAD").write_text(COMMIT + "\n")
    repo = tmp_path / "repos" / "r"
    repo.mkdir(parents=True)
    (repo / ".git").write_text("gitdir: ../../real_git_dir\n")
    assert sbom.git_commit(repo) == COMMIT


def test_commit_from_worktree_uses_common_dir(tmp_path):
    main_git = tmp_path / "main" / ".git"
    (main_git / "refs" / "heads").mkdir(parents=True)
    (main_git / "refs" / "heads" / "feature").write_text(COMMIT + "\n")
    worktree_git = main_git / "worktrees" / "wt"
    worktree_git.mkdir(parents=True)
    (worktree_git / "HEAD").write_text("ref: refs/heads/feature\n")
    (worktree_git / "commondir").write_text("../..\n")
    repo = tmp_path / "wt"
    repo.mkdir()
    (repo / ".git").write_text(f"gitdir: {worktree_git}\n")
    assert sbom.git_commit(repo) == COMMIT


def test_commit_missing(tmp_path):
    repo = make_repo(tmp_path, "r")
    assert sbom.git_commit(repo) == ""


@pytest.mark.parametrize(
    "files",
    [
        {"HEAD": "ref: refs/heads/main\n"},  # branch without commits
        {"HEAD": "not a hash\n"},
        {"HEAD": "g" * 40 + "\n"},
        {"HEAD": ""},
        {"HEAD": "ref: refs/heads/a\n", "refs/heads/a": "ref: refs/heads/b\n",
         "refs/heads/b": "ref: refs/heads/a\n"},  # loop
    ],
)
def test_commit_unusable_head(tmp_path, files):
    repo = make_repo(tmp_path, "r")
    write_git(repo, files)
    assert sbom.git_commit(repo) == ""


def test_commit_ref_cannot_escape_git_dir(tmp_path):
    repo = make_repo(tmp_path, "r")
    write_git(repo, {"HEAD": "ref: ../../secret\n"})
    (tmp_path / "secret").write_text(COMMIT + "\n")
    assert sbom.git_commit(repo) == ""


# --- output -----------------------------------------------------------------


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

    rows = read_csv(tmp_path)
    assert [(r["name"], r["version"], r["type"], r["scope"]) for r in rows] == [
        ("requests", "2.31.0", "pip", "runtime"),
        ("react", "^18.2.0", "npm", "runtime"),
        ("jest", "29.7.0", "npm", "dev"),
    ]
    assert rows[0]["path"] == str(tmp_path / "a" / "requirements.txt")
    assert rows[0]["repository"] == "a"

    data = read_json(tmp_path)
    assert data["dependencies"] == rows
    assert [r["name"] for r in data["repositories"]] == ["a", "b"]


def test_csv_header(tmp_path):
    make_repo(tmp_path, "a", requirements="flask\n")
    run_cli(tmp_path)
    with open(tmp_path / "sbom.csv", newline="", encoding="utf-8") as f:
        assert next(csv.reader(f)) == list(sbom.COLUMNS)


def test_json_header_and_repositories(tmp_path):
    repo = make_repo(tmp_path, "a", requirements="flask\nrequests\n")
    write_git(repo, {"HEAD": COMMIT + "\n"})
    run_cli(tmp_path)
    data = read_json(tmp_path)
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", data["generated_at"])
    assert data["tool"] == "sbom.py"
    assert data["root"] == str(tmp_path)
    assert data["repositories"] == [
        {
            "name": "a",
            "path": str(repo),
            "commit": COMMIT,
            "files": [str(repo / "requirements.txt")],
            "dependency_count": 2,
        }
    ]


def test_relative_path_gives_absolute_output(tmp_path, monkeypatch, capsys):
    make_repo(tmp_path, "a", requirements="flask\n")
    monkeypatch.chdir(tmp_path)
    assert run_cli(".") == 0
    assert f"Found 1 repository in '{tmp_path}'" in capsys.readouterr().out
    assert read_csv(tmp_path)[0]["path"] == str(tmp_path / "a" / "requirements.txt")


def test_old_output_is_overwritten(tmp_path):
    make_repo(tmp_path, "a", requirements="flask\n")
    (tmp_path / "sbom.csv").write_text("old content that is much longer than the new\n" * 50)
    run_cli(tmp_path)
    assert [r["name"] for r in read_csv(tmp_path)] == ["flask"]


def test_special_characters_survive_csv(tmp_path):
    make_repo(
        tmp_path,
        "repo, with \"quotes\"",
        package_json={"dependencies": {"comma,name": "1.0.0", "new\nline": "1.0.0", "æøå": "1.0.0"}},
    )
    run_cli(tmp_path)
    rows = read_csv(tmp_path)
    assert [r["name"] for r in rows] == ["comma,name", "new\nline", "æøå"]
    assert rows[0]["repository"] == 'repo, with "quotes"'
    assert read_json(tmp_path)["dependencies"] == rows


def test_non_utf8_folder_name(tmp_path):
    if sys.platform in ("darwin", "win32"):
        pytest.skip("file system only allows valid Unicode names")
    make_repo(tmp_path, os.fsdecode(b"bad\xff"), requirements="flask\n")
    assert run_cli(tmp_path) == 0
    assert read_csv(tmp_path)[0]["repository"] == "bad\\udcff"
    assert read_json(tmp_path)["dependencies"][0]["name"] == "flask"


# --- CSV formula escaping ---------------------------------------------------


def test_csv_escapes_formulas(tmp_path):
    make_repo(tmp_path, "a", requirements="foo==1.*\nbar==2.0\n")
    make_repo(
        tmp_path,
        "b",
        package_json={"dependencies": {'=HYPERLINK("http://x")': "1.0.0", "baz": "=1.0.0"}},
    )
    assert run_cli(tmp_path) == 0

    assert [(r["name"], r["version"]) for r in read_csv(tmp_path)] == [
        ("foo", "'==1.*"),
        ("bar", "2.0"),
        ("'=HYPERLINK(\"http://x\")", "1.0.0"),
        ("baz", "'=1.0.0"),
    ]
    assert [(d["name"], d["version"]) for d in read_json(tmp_path)["dependencies"]] == [
        ("foo", "==1.*"),
        ("bar", "2.0"),
        ('=HYPERLINK("http://x")', "1.0.0"),
        ("baz", "=1.0.0"),
    ]


def test_csv_escapes_formula_in_repository_name(tmp_path):
    make_repo(tmp_path, "=cmd", requirements="flask\n")
    run_cli(tmp_path)
    assert read_csv(tmp_path)[0]["repository"] == "'=cmd"
    assert read_json(tmp_path)["dependencies"][0]["repository"] == "=cmd"


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
    assert [r["name"] for r in read_csv(tmp_path)] == ["@emotion/react", "@babel/core"]


# --- command line and errors ------------------------------------------------


def test_missing_directory_exits_nonzero(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["sbom.py", str(tmp_path / "nope")])
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(SBOM_SCRIPT, run_name="__main__")
    assert exc.value.code == 1


def test_missing_directory_message(tmp_path, capsys):
    assert run_cli(tmp_path / "nope") == 1
    assert "does not exist" in capsys.readouterr().err


def test_path_is_a_file(tmp_path, capsys):
    f = tmp_path / "file.txt"
    f.write_text("")
    assert run_cli(f) == 1
    assert "is not a directory" in capsys.readouterr().err


def test_no_repositories(tmp_path, capsys):
    assert run_cli(tmp_path) == 1
    assert "no git repositories found" in capsys.readouterr().err
    assert not (tmp_path / "sbom.csv").exists()


def test_directory_is_itself_a_repo(tmp_path, capsys):
    (tmp_path / ".git").mkdir()
    assert run_cli(tmp_path) == 1
    assert "is itself a git repository" in capsys.readouterr().err


def test_wrong_number_of_arguments(tmp_path, capsys):
    assert run_cli() == 2
    assert run_cli(tmp_path, tmp_path) == 2
    assert "usage" in capsys.readouterr().err


def test_unknown_option(tmp_path):
    assert run_cli("--verbose", tmp_path) == 2


def test_help(capsys):
    assert run_cli("--help") == 0
    assert "usage" in capsys.readouterr().out


def test_repo_without_dependency_files_is_skipped(tmp_path, capsys):
    make_repo(tmp_path, "empty")
    make_repo(tmp_path, "app", requirements="flask\n")
    assert run_cli(tmp_path) == 0
    assert "no requirements.txt or package.json" in capsys.readouterr().err
    assert [r["name"] for r in read_json(tmp_path)["repositories"]] == ["app"]


def test_only_empty_repos_gives_empty_sbom(tmp_path):
    make_repo(tmp_path, "empty")
    assert run_cli(tmp_path) == 0
    assert read_csv(tmp_path) == []
    assert read_json(tmp_path)["dependencies"] == []


def test_invalid_package_json_is_reported(tmp_path, capsys):
    bad = make_repo(tmp_path, "bad")
    (bad / "package.json").write_text("{not json")
    make_repo(tmp_path, "good", requirements="flask\n")
    assert run_cli(tmp_path) == 1
    assert "not valid JSON" in capsys.readouterr().err
    assert [r["name"] for r in read_csv(tmp_path)] == ["flask"]


def test_deeply_nested_package_json_does_not_crash(tmp_path, capsys):
    bad = make_repo(tmp_path, "evil")
    (bad / "package.json").write_text("[" * 100_000)
    make_repo(tmp_path, "good", requirements="flask\n")
    assert run_cli(tmp_path) == 1
    assert "skipping 'evil'" in capsys.readouterr().err
    assert [r["name"] for r in read_csv(tmp_path)] == ["flask"]


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="needs a non-root user"
)
def test_unwritable_output_directory(tmp_path, capsys):
    make_repo(tmp_path, "a", requirements="flask\n")
    tmp_path.chmod(0o555)
    try:
        assert run_cli(tmp_path) == 1
    finally:
        tmp_path.chmod(0o755)
    assert "could not write SBOM" in capsys.readouterr().err


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="needs a non-root user"
)
def test_unreadable_dependency_file(tmp_path, capsys):
    repo = make_repo(tmp_path, "a", requirements="flask\n")
    (repo / "requirements.txt").chmod(0o000)
    try:
        assert run_cli(tmp_path) == 1
    finally:
        (repo / "requirements.txt").chmod(0o644)
    assert "could not read" in capsys.readouterr().err


# --- package-lock.json (indirect dependencies) ------------------------------


def write_lock(repo, content):
    path = repo / "package-lock.json"
    path.write_text(content if isinstance(content, str) else json.dumps(content))
    return path


def lock_rows(deps):
    return [(d["name"], d["version"], d["scope"], d["relationship"]) for d in deps]


V3_LOCK = {
    "name": "app",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "app", "dependencies": {"react": "^18.2.0"}},
        "node_modules/react": {"version": "18.2.0"},
        "node_modules/jest": {"version": "29.7.0", "dev": True},
        "node_modules/loose-envify": {"version": "1.4.0"},
        "node_modules/@babel/core": {"version": "7.25.2", "dev": True},
        "node_modules/fsevents": {"version": "2.3.3", "optional": True},
        "node_modules/devopt": {"version": "1.0.0", "devOptional": True},
        "node_modules/some-peer": {"version": "2.0.0", "peer": True},
        "node_modules/jest/node_modules/react": {"version": "17.0.2", "dev": True},
    },
}


def test_lock_v3_indirect_dependencies(tmp_path):
    lock = write_lock(tmp_path, V3_LOCK)
    deps = sbom.parse_package_lock(lock, {"react", "jest"})
    assert lock_rows(deps) == [
        ("loose-envify", "1.4.0", "runtime", "indirect"),
        ("@babel/core", "7.25.2", "dev", "indirect"),
        ("fsevents", "2.3.3", "optional", "indirect"),
        ("devopt", "1.0.0", "dev", "indirect"),
        ("some-peer", "2.0.0", "peer", "indirect"),
        ("react", "17.0.2", "dev", "indirect"),
    ]
    assert {d["path"] for d in deps} == {str(lock)}
    assert deps[1]["purl"] == "pkg:npm/%40babel/core@7.25.2"


def test_lock_without_direct_names_lists_everything(tmp_path):
    lock = write_lock(tmp_path, V3_LOCK)
    assert len(sbom.parse_package_lock(lock, set())) == 8


def test_lock_same_package_in_several_versions(tmp_path):
    lock = write_lock(
        tmp_path,
        {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/a/node_modules/types": {"version": "7.17.0"},
                "node_modules/b/node_modules/types": {"version": "7.17.0"},
                "node_modules/c/node_modules/types": {"version": "7.25.2"},
                "node_modules/d/node_modules/types": {"version": "7.25.2", "dev": True},
            },
        },
    )
    assert lock_rows(sbom.parse_package_lock(lock, set())) == [
        ("types", "7.17.0", "runtime", "indirect"),
        ("types", "7.25.2", "runtime", "indirect"),
        ("types", "7.25.2", "dev", "indirect"),
    ]


def test_lock_skips_project_links_and_workspaces(tmp_path):
    lock = write_lock(
        tmp_path,
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "packages/ui": {"name": "ui", "version": "1.0.0"},
                "node_modules/ui": {"resolved": "packages/ui", "link": True},
                "node_modules/real": {"version": "1.0.0"},
            },
        },
    )
    assert [d["name"] for d in sbom.parse_package_lock(lock, set())] == ["real"]


def test_lock_v2_reads_packages_only_once(tmp_path):
    lock = write_lock(
        tmp_path,
        {
            "lockfileVersion": 2,
            "packages": {"node_modules/a": {"version": "1.0.0"}},
            "dependencies": {"a": {"version": "1.0.0"}},
        },
    )
    assert lock_rows(sbom.parse_package_lock(lock, set())) == [
        ("a", "1.0.0", "runtime", "indirect"),
    ]


def test_lock_v1_nested_tree(tmp_path):
    lock = write_lock(
        tmp_path,
        {
            "lockfileVersion": 1,
            "dependencies": {
                "react": {"version": "18.2.0"},
                "loose-envify": {"version": "1.4.0"},
                "jest": {
                    "version": "29.7.0",
                    "dev": True,
                    "dependencies": {"react": {"version": "17.0.2", "dev": True}},
                },
                "fsevents": {"version": "2.3.3", "optional": True},
            },
        },
    )
    assert lock_rows(sbom.parse_package_lock(lock, {"react", "jest"})) == [
        ("loose-envify", "1.4.0", "runtime", "indirect"),
        ("fsevents", "2.3.3", "optional", "indirect"),
        ("react", "17.0.2", "dev", "indirect"),
    ]


@pytest.mark.parametrize(
    "content",
    [
        {"lockfileVersion": 3, "packages": {"node_modules/a": "not an object"}},
        {"lockfileVersion": 3, "packages": "not an object"},
        {"lockfileVersion": 1, "dependencies": {"a": None}},
        {"lockfileVersion": 3},
        {},
    ],
)
def test_lock_odd_content_gives_no_rows(tmp_path, content):
    assert sbom.parse_package_lock(write_lock(tmp_path, content), set()) == []


def test_lock_non_string_version(tmp_path):
    lock = write_lock(tmp_path, {"packages": {"node_modules/a": {"version": 5}}})
    assert sbom.parse_package_lock(lock, set())[0]["version"] == ""


@pytest.mark.parametrize(
    "content, message",
    [
        ("{not json", "not valid JSON"),
        ("[]", "does not contain a JSON object"),
        ("[" * 100_000, "not valid JSON"),
    ],
)
def test_invalid_lock(tmp_path, content, message):
    with pytest.raises(sbom.DependencyFileError, match=message):
        sbom.parse_package_lock(write_lock(tmp_path, content), set())


def test_relationship_in_sbom(tmp_path):
    make_repo(tmp_path, "py", requirements="flask\n")
    repo = make_repo(
        tmp_path,
        "web",
        package_json={"dependencies": {"react": "^18.2.0"}},
    )
    write_lock(repo, V3_LOCK)
    assert run_cli(tmp_path) == 0

    rows = read_csv(tmp_path)
    assert [(r["repository"], r["name"], r["version"], r["relationship"]) for r in rows] == [
        ("py", "flask", "", "direct"),
        ("web", "react", "^18.2.0", "direct"),
        ("web", "jest", "29.7.0", "indirect"),
        ("web", "loose-envify", "1.4.0", "indirect"),
        ("web", "@babel/core", "7.25.2", "indirect"),
        ("web", "fsevents", "2.3.3", "indirect"),
        ("web", "devopt", "1.0.0", "indirect"),
        ("web", "some-peer", "2.0.0", "indirect"),
        ("web", "react", "17.0.2", "indirect"),
    ]
    assert read_json(tmp_path)["dependencies"] == rows

    web = read_json(tmp_path)["repositories"][1]
    assert web["files"] == [str(repo / "package.json"), str(repo / "package-lock.json")]
    assert web["dependency_count"] == 8


def test_lock_ignored_without_package_json(tmp_path, capsys):
    only_lock = make_repo(tmp_path, "only_lock")
    write_lock(only_lock, V3_LOCK)
    python = make_repo(tmp_path, "python", requirements="flask\n")
    write_lock(python, V3_LOCK)
    assert run_cli(tmp_path) == 0
    assert "no requirements.txt or package.json in" in capsys.readouterr().err
    assert [r["name"] for r in read_csv(tmp_path)] == ["flask"]


def test_invalid_lock_skips_repo(tmp_path, capsys):
    bad = make_repo(tmp_path, "bad", package_json={"dependencies": {"react": "18.2.0"}})
    write_lock(bad, "{not json")
    make_repo(tmp_path, "good", requirements="flask\n")
    assert run_cli(tmp_path) == 1
    err = capsys.readouterr().err
    assert "skipping 'bad'" in err and "package-lock.json" in err
    assert [r["name"] for r in read_csv(tmp_path)] == ["flask"]


def test_deep_v1_lock_does_not_crash(tmp_path):
    repo = make_repo(tmp_path, "deep", package_json={"dependencies": {}})
    depth = 3000
    write_lock(
        repo,
        '{"lockfileVersion": 1, "dependencies": '
        + '{"a": {"version": "1.0.0", "dependencies": ' * depth
        + "{}"
        + "}}" * depth
        + "}",
    )
    # Either parsed (and walked without recursion) or rejected as too deep,
    # but never a crash.
    assert run_cli(tmp_path) in (0, 1)
