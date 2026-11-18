"""Generate a software bill of materials (SBOM) for a directory of git repositories.

Usage:
    python3 sbom.py <directory>

Every immediate subdirectory of <directory> that is a git repository is scanned
for requirements.txt and package.json. The result is written to sbom.csv and
sbom.json in <directory>.
"""

import argparse
import csv
import json
import os
import re
import string
import sys
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone

# Checked before the imports below, which fail on older versions
if sys.version_info < (3, 10):
    sys.exit(
        f"Error: sbom.py requires Python 3.10 or newer, "
        f"this is Python {sys.version.split()[0]}"
    )

from typing import TypedDict  # noqa: E402

from dependency_reader import (  # noqa: E402
    PACKAGE_JSON_FILE,
    REQUIREMENTS_FILE,
    Dependency,
    DependencyFileError,
    StrPath,
    find_dependency_files,
    parse_package_json,
    parse_package_lock,
    parse_requirements,
    read_repo,
)

__all__ = [
    "Dependency",
    "DependencyFileError",
    "RepositoryInfo",
    "find_repos",
    "git_commit",
    "parse_package_json",
    "parse_package_lock",
    "parse_requirements",
    "run",
    "scan",
    "write_csv",
    "write_json",
]

CSV_FILE = "sbom.csv"
JSON_FILE = "sbom.json"
COLUMNS = (
    "name",
    "version",
    "type",
    "path",
    "scope",
    "relationship",
    "purl",
    "repository",
    "commit",
)

# Spreadsheet programs treat cells starting with these as formulas
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

# Scoped npm package names such as '@babel/core' start with '@', but npm only
# allows characters that can't form a formula call, so they are left as is.
SCOPED_NPM_NAME = re.compile(r"@[a-z0-9~-][a-z0-9._~-]*/[a-z0-9~-][a-z0-9._~-]*")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


class RepositoryInfo(TypedDict):
    """Summary of one scanned repository, as written to sbom.json."""
    name: str
    path: str
    commit: str
    files: list[str]
    dependency_count: int


# --- repositories -----------------------------------------------------------


def find_repos(root: StrPath) -> list[str]:
    """Return the absolute paths of the git repositories directly inside root, sorted."""
    root = os.path.abspath(root)
    repos: list[str] = []
    with os.scandir(root) as entries:
        for entry in entries:
            if entry.is_dir() and os.path.exists(os.path.join(entry.path, ".git")):
                repos.append(entry.path)
    return sorted(repos)


def scan(root: StrPath) -> list[Dependency]:
    """Return all dependencies of all repositories directly inside root."""
    dependencies: list[Dependency] = []
    for repo in find_repos(root):
        dependencies.extend(_scan_repo(repo))
    return dependencies


def _scan_repo(repo: str, commit: str | None = None) -> list[Dependency]:
    """Return one repository's dependencies, each tagged with its commit."""
    if commit is None:
        commit = git_commit(repo)
    dependencies = read_repo(repo)
    for dep in dependencies:
        dep["commit"] = commit
    return dependencies


# --- git commit -------------------------------------------------------------


def git_commit(repo_path: StrPath) -> str:
    """Return the commit hash HEAD points to, or "" if it can't be determined.

    Reads the files in .git directly instead of running git.
    """
    git_dir = _git_dir(repo_path)
    if git_dir is None:
        return ""
    common_dir = _common_dir(git_dir)

    value = _read_first_line(os.path.join(git_dir, "HEAD"))
    # Follow symbolic refs, with a limit in case of a loop
    for _ in range(10):
        if value is None:
            return ""
        if not value.startswith("ref:"):
            return value if _is_hash(value) else ""
        value = _read_ref(git_dir, common_dir, value[4:].strip())
    return ""


def _git_dir(repo_path: StrPath) -> str | None:
    """Return the repository's git directory, following a .git file if needed."""
    dot_git = os.path.join(repo_path, ".git")
    if os.path.isdir(dot_git):
        return dot_git
    # Worktrees and submodules have a .git file containing 'gitdir: <path>'
    line = _read_first_line(dot_git)
    if line and line.startswith("gitdir:"):
        path = os.path.join(repo_path, line[7:].strip())
        if os.path.isdir(path):
            return os.path.normpath(path)
    return None


def _common_dir(git_dir: str) -> str:
    """Return the directory holding the shared refs (not git_dir in worktrees)."""
    line = _read_first_line(os.path.join(git_dir, "commondir"))
    if line:
        path = os.path.normpath(os.path.join(git_dir, line))
        if os.path.isdir(path):
            return path
    return git_dir


def _read_ref(git_dir: str, common_dir: str, ref: str) -> str | None:
    """Return what a ref such as 'refs/heads/main' points to, or None."""
    if ".." in ref.split("/"):
        return None
    for base in dict.fromkeys((git_dir, common_dir)):
        value = _read_first_line(os.path.join(base, *ref.split("/")))
        if value:
            return value
    return _packed_ref(common_dir, ref)


def _packed_ref(git_dir: str, ref: str) -> str | None:
    """Look up a ref in packed-refs, where git stores refs in bulk."""
    try:
        with open(os.path.join(git_dir, "packed-refs"), encoding="utf-8") as f:
            for line in f:
                if line.startswith(("#", "^")):
                    continue
                parts = line.split()
                if len(parts) == 2 and parts[1] == ref:
                    return parts[0]
    except (OSError, UnicodeDecodeError):
        pass
    return None


def _read_first_line(path: str) -> str | None:
    """Return the first line of a file, stripped, or None if unreadable."""
    try:
        with open(path, encoding="utf-8") as f:
            return f.readline().strip()
    except (OSError, UnicodeDecodeError):
        return None


def _is_hash(value: str) -> bool:
    """Return True if value looks like a git commit hash (SHA-1 or SHA-256)."""
    return len(value) in (40, 64) and all(c in string.hexdigits for c in value)


# --- output -----------------------------------------------------------------


def write_csv(dependencies: Iterable[Dependency], path: StrPath) -> None:
    """Write the dependencies to a CSV file, one row per dependency."""
    with open(path, "w", newline="", encoding="utf-8", errors="backslashreplace") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for dep in dependencies:
            writer.writerow({col: _csv_safe(dep.get(col, "")) for col in COLUMNS})


def _csv_safe(value: str) -> str:
    """Prefix value with ' so spreadsheet programs show it as text, not a formula.

    Package names and versions come from files in the scanned repositories, so
    a value like '=HYPERLINK(...)' must not run when sbom.csv is opened.
    """
    if value.startswith(FORMULA_PREFIXES) and not SCOPED_NPM_NAME.fullmatch(value):
        return "'" + value
    return value


def write_json(
    dependencies: Iterable[Dependency],
    path: StrPath,
    root: StrPath,
    repositories: Iterable[RepositoryInfo] = (),
) -> None:
    """Write the dependencies and repository summaries to a JSON file."""
    document = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool": "sbom.py",
        "root": os.path.abspath(root),
        "repositories": list(repositories),
        "dependencies": [{col: dep.get(col, "") for col in COLUMNS} for dep in dependencies],
    }
    # backslashreplace: file names that aren't valid UTF-8 are written as \udcff etc.
    with open(path, "w", encoding="utf-8", errors="backslashreplace") as f:
        json.dump(document, f, indent=2, ensure_ascii=False)
        f.write("\n")


# --- command line -----------------------------------------------------------


def _plural(count: int, singular: str, plural: str) -> str:
    """Return e.g. '1 repository' or '3 repositories'."""
    return f"{count} {singular if count == 1 else plural}"


def _error(message: str) -> None:
    """Print an error message to stderr."""
    print(f"Error: {message}", file=sys.stderr)


def _warning(message: str) -> None:
    """Print a warning to stderr."""
    print(f"Warning: {message}", file=sys.stderr)


class _Exit(Exception):
    """Stops the tool with an exit code and an optional error message."""

    def __init__(self, code: int, message: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _parse_args(argv: Sequence[str]) -> str:
    """Return the absolute path of the directory given on the command line."""
    parser = argparse.ArgumentParser(
        prog="sbom.py",
        description=(
            "Scan every git repository directly inside DIRECTORY for "
            f"{REQUIREMENTS_FILE} and {PACKAGE_JSON_FILE}, and save the dependencies "
            f"to {CSV_FILE} and {JSON_FILE} in DIRECTORY."
        ),
    )
    parser.add_argument("directory", help="directory containing the git repositories")
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        # argparse has already printed the help text or the usage error
        raise _Exit(EXIT_OK if e.code == 0 else EXIT_USAGE) from None
    directory: str = args.directory
    return os.path.abspath(directory)


def _find_repos_in(root: str) -> list[str]:
    """Like find_repos(), but raises _Exit with a helpful message on failure."""
    if not os.path.exists(root):
        raise _Exit(EXIT_ERROR, f"'{root}' does not exist")
    if not os.path.isdir(root):
        raise _Exit(EXIT_ERROR, f"'{root}' is not a directory")
    try:
        repos = find_repos(root)
    except OSError as e:
        raise _Exit(EXIT_ERROR, f"could not read '{root}': {e.strerror}") from e
    if not repos:
        raise _Exit(EXIT_ERROR, _no_repos_message(root))
    return repos


def _no_repos_message(root: str) -> str:
    """Return the 'no repositories' error, with a hint if root is a repo itself."""
    message = f"no git repositories found in '{root}'"
    if os.path.exists(os.path.join(root, ".git")):
        message += (
            f"\n'{root}' is itself a git repository. Pass the directory that "
            "contains your repositories instead."
        )
    return message


def _read_repo_info(repo: str) -> tuple[list[Dependency], RepositoryInfo] | None:
    """Return the dependencies and summary of one repository, or None to skip it."""
    files = find_dependency_files(repo)
    if not files:
        _warning(f"no {REQUIREMENTS_FILE} or {PACKAGE_JSON_FILE} in '{repo}', skipping")
        return None
    commit = git_commit(repo)
    dependencies = _scan_repo(repo, commit)
    info: RepositoryInfo = {
        "name": os.path.basename(repo),
        "path": repo,
        "commit": commit,
        "files": files,
        "dependency_count": len(dependencies),
    }
    return dependencies, info


def _scan_repos(
    repos: Iterable[str],
) -> tuple[list[Dependency], list[RepositoryInfo], bool]:
    """Scan every repository, reporting broken ones instead of stopping.

    Returns the dependencies, the repositories they came from, and whether
    any repository failed.
    """
    dependencies: list[Dependency] = []
    repositories: list[RepositoryInfo] = []
    failed = False
    for repo in repos:
        try:
            result = _read_repo_info(repo)
        except (OSError, DependencyFileError) as e:
            _error(f"skipping '{os.path.basename(repo)}': {e}")
            failed = True
            continue
        if result is not None:
            dependencies.extend(result[0])
            repositories.append(result[1])
    return dependencies, repositories, failed


def _save(
    root: str, dependencies: list[Dependency], repositories: list[RepositoryInfo]
) -> None:
    """Write sbom.csv and sbom.json into root and print where they were saved."""
    csv_path = os.path.join(root, CSV_FILE)
    json_path = os.path.join(root, JSON_FILE)
    try:
        write_csv(dependencies, csv_path)
        print(f"Saved SBOM in CSV format to '{csv_path}'")
        write_json(dependencies, json_path, root, repositories)
        print(f"Saved SBOM in JSON format to '{json_path}'")
    except OSError as e:
        raise _Exit(EXIT_ERROR, f"could not write SBOM: {e}") from e


def run(argv: Sequence[str]) -> int:
    """Run the command line tool and return its exit code."""
    try:
        root = _parse_args(argv)
        repos = _find_repos_in(root)
        print(f"Found {_plural(len(repos), 'repository', 'repositories')} in '{root}'")
        dependencies, repositories, failed = _scan_repos(repos)
        _save(root, dependencies, repositories)
    except _Exit as e:
        if e.message:
            _error(e.message)
        return e.code
    return EXIT_ERROR if failed else EXIT_OK


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
