"""Tests for unusual input that is unlikely in practice.

Not run in CI. Run with: python -m pytest edge_cases.py -v

Tests marked xfail are known issues. They are expected to fail until the
issue is fixed; strict=True makes the run fail if one starts passing, so
the marker gets removed together with the fix.
"""

import os
import subprocess
import sys

import pytest

import dependency_reader
from tests import SBOM_SCRIPT, make_repo, read_csv, read_json, run_cli

needs_symlinks = pytest.mark.skipif(os.name == "nt", reason="needs symlinks")
needs_non_root = pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="needs a non-root user"
)


# --- requirements.txt -------------------------------------------------------


def test_continuation_at_end_of_file(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("flask==3.0.0 \\")
    deps = dependency_reader.parse_requirements(f)
    assert [(d["name"], d["version"]) for d in deps] == [("flask", "3.0.0")]


def test_names_differing_only_in_case_give_two_rows(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("flask==3.0.0\nFlask==3.0.0\n")
    deps = dependency_reader.parse_requirements(f)
    assert [d["name"] for d in deps] == ["flask", "Flask"]
    assert {d["purl"] for d in deps} == {"pkg:pypi/flask@3.0.0"}


def test_uppercase_file_name_is_not_found(tmp_path):
    repo = make_repo(tmp_path, "a")
    (repo / "Requirements.txt").write_text("flask\n")
    if (repo / "requirements.txt").exists():
        pytest.skip("case-insensitive file system")
    assert dependency_reader.find_dependency_files(repo) == []


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_named_pipe_is_skipped_without_hanging(tmp_path):
    repo = make_repo(tmp_path, "a")
    os.mkfifo(repo / "requirements.txt")
    # In a subprocess, so a regression fails the test instead of hanging it
    result = subprocess.run(
        [sys.executable, SBOM_SCRIPT, str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "no requirements.txt or package.json" in result.stderr


@pytest.mark.xfail(strict=True, reason="only UTF-8 is read")
def test_utf16_requirements(tmp_path):
    # What 'pip freeze > requirements.txt' writes in Windows PowerShell 5.1
    f = tmp_path / "requirements.txt"
    f.write_bytes("flask==3.0.0\r\n".encode("utf-16"))
    deps = dependency_reader.parse_requirements(f)
    assert [(d["name"], d["version"]) for d in deps] == [("flask", "3.0.0")]


# --- package.json -----------------------------------------------------------


def test_dependencies_as_list_are_ignored(tmp_path):
    repo = make_repo(
        tmp_path,
        "a",
        package_json={"dependencies": ["react"], "devDependencies": {"jest": "29.0.0"}},
    )
    assert [d["name"] for d in dependency_reader.read_repo(repo)] == ["jest"]


@pytest.mark.xfail(strict=True, reason="npm versions are not stripped")
def test_npm_version_whitespace_is_stripped(tmp_path):
    repo = make_repo(
        tmp_path, "a", package_json={"dependencies": {"react": " 18.2.0 "}}
    )
    dep = dependency_reader.read_repo(repo)[0]
    assert dep["version"] == "18.2.0"


def test_empty_dependency_files(tmp_path):
    make_repo(tmp_path, "a", requirements="", package_json={})
    assert run_cli(tmp_path) == 0
    assert read_csv(tmp_path) == []
    [repo] = read_json(tmp_path)["repositories"]
    assert repo["dependency_count"] == 0
    assert len(repo["files"]) == 2


# --- symlinks ---------------------------------------------------------------


@needs_symlinks
def test_symlink_to_non_requirements_file_gives_no_rows(tmp_path):
    outside = tmp_path / "passwd"
    outside.write_text("root:x:0:0:root:/root:/bin/bash\nbin:x:1:1::/:/sbin/nologin\n")
    root = tmp_path / "repos"
    repo = make_repo(root, "a")
    os.symlink(outside, repo / "requirements.txt")
    assert run_cli(root) == 0
    assert read_csv(root) == []


@needs_symlinks
def test_symlinked_requirements_outside_repo_is_followed(tmp_path):
    outside = tmp_path / "shared.txt"
    outside.write_text("flask==3.0.0\n")
    root = tmp_path / "repos"
    repo = make_repo(root, "a")
    os.symlink(outside, repo / "requirements.txt")
    assert run_cli(root) == 0
    [row] = read_csv(root)
    assert row["name"] == "flask"
    assert row["path"] == str(repo / "requirements.txt")


@needs_symlinks
def test_symlink_back_to_root_does_not_loop(tmp_path):
    make_repo(tmp_path, "a", requirements="flask\n")
    os.symlink(tmp_path, tmp_path / "loop")
    assert run_cli(tmp_path) == 0
    assert [r["name"] for r in read_json(tmp_path)["repositories"]] == ["a"]


@needs_symlinks
def test_repository_linked_twice_is_listed_twice(tmp_path):
    make_repo(tmp_path, "a", requirements="flask\n")
    os.symlink(tmp_path / "a", tmp_path / "b")
    assert run_cli(tmp_path) == 0
    assert [r["repository"] for r in read_csv(tmp_path)] == ["a", "b"]


# --- repositories and git ---------------------------------------------------


def test_hidden_directory_is_scanned(tmp_path):
    make_repo(tmp_path, ".hidden", requirements="flask\n")
    assert run_cli(tmp_path) == 0
    assert [r["repository"] for r in read_csv(tmp_path)] == [".hidden"]


@pytest.mark.skipif(os.name == "nt", reason="newlines aren't allowed in names")
def test_repository_name_with_comma_and_newline(tmp_path):
    make_repo(tmp_path, "we,ird\nname", requirements="flask\n")
    assert run_cli(tmp_path) == 0
    [row] = read_csv(tmp_path)
    assert row["repository"] == "we,ird\nname"
    assert row["name"] == "flask"


def test_git_file_pointing_nowhere_gives_empty_commit(tmp_path):
    repo = tmp_path / "a"
    repo.mkdir()
    (repo / ".git").write_text("gitdir: /does/not/exist\n")
    (repo / "requirements.txt").write_text("flask\n")
    assert run_cli(tmp_path) == 0
    assert read_csv(tmp_path)[0]["commit"] == ""


# --- errors -----------------------------------------------------------------


@needs_non_root
def test_directory_that_cannot_be_listed(tmp_path, capsys):
    root = tmp_path / "repos"
    make_repo(root, "a", requirements="flask\n")
    root.chmod(0o300)
    try:
        assert run_cli(root) == 1
    finally:
        root.chmod(0o755)
    assert "could not read" in capsys.readouterr().err


@pytest.mark.xfail(strict=True, reason="sbom.csv is written before sbom.json")
def test_failed_json_write_leaves_old_csv(tmp_path):
    make_repo(tmp_path, "a", requirements="flask\n")
    (tmp_path / "sbom.csv").write_text("old\n")
    (tmp_path / "sbom.json").mkdir()
    assert run_cli(tmp_path) == 1
    assert (tmp_path / "sbom.csv").read_text() == "old\n"
