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
import string
import sys
from datetime import datetime, timezone

from dependency_reader import (
    PACKAGE_JSON_FILE,
    REQUIREMENTS_FILE,
    DependencyFileError,
    find_dependency_files,
    parse_package_json,
    parse_requirements,
    read_repo,
)

__all__ = [
    "DependencyFileError",
    "find_repos",
    "git_commit",
    "main",
    "parse_package_json",
    "parse_requirements",
    "run",
    "scan",
    "write_csv",
    "write_json",
]

CSV_FILE = "sbom.csv"
JSON_FILE = "sbom.json"
COLUMNS = ("name", "version", "type", "path", "scope", "purl", "repository", "commit")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


# --- repositories -----------------------------------------------------------


def find_repos(root):
    """Return the absolute paths of the git repositories directly inside root, sorted."""
    root = os.path.abspath(root)
    repos = []
    with os.scandir(root) as entries:
        for entry in entries:
            if entry.is_dir() and os.path.exists(os.path.join(entry.path, ".git")):
                repos.append(entry.path)
    return sorted(repos)


def scan(root):
    """Return all dependencies of all repositories directly inside root."""
    dependencies = []
    for repo in find_repos(root):
        dependencies.extend(_scan_repo(repo))
    return dependencies


def _scan_repo(repo, commit=None):
    if commit is None:
        commit = git_commit(repo)
    dependencies = read_repo(repo)
    for dep in dependencies:
        dep["commit"] = commit
    return dependencies


# --- git commit -------------------------------------------------------------


def git_commit(repo_path):
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


def _git_dir(repo_path):
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


def _common_dir(git_dir):
    line = _read_first_line(os.path.join(git_dir, "commondir"))
    if line:
        path = os.path.normpath(os.path.join(git_dir, line))
        if os.path.isdir(path):
            return path
    return git_dir


def _read_ref(git_dir, common_dir, ref):
    if ".." in ref.split("/"):
        return None
    for base in dict.fromkeys((git_dir, common_dir)):
        value = _read_first_line(os.path.join(base, *ref.split("/")))
        if value:
            return value
    return _packed_ref(common_dir, ref)


def _packed_ref(git_dir, ref):
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


def _read_first_line(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.readline().strip()
    except (OSError, UnicodeDecodeError):
        return None


def _is_hash(value):
    return len(value) in (40, 64) and all(c in string.hexdigits for c in value)


# --- output -----------------------------------------------------------------


def write_csv(dependencies, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for dep in dependencies:
            writer.writerow({col: dep.get(col, "") for col in COLUMNS})


def write_json(dependencies, path, root, repositories=()):
    document = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool": "sbom.py",
        "root": os.path.abspath(root),
        "repositories": list(repositories),
        "dependencies": [{col: dep.get(col, "") for col in COLUMNS} for dep in dependencies],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(document, f, indent=2, ensure_ascii=False)
        f.write("\n")


# --- command line -----------------------------------------------------------


def _plural(count, singular, plural):
    return f"{count} {singular if count == 1 else plural}"


def _error(message):
    print(f"Error: {message}", file=sys.stderr)


def _warning(message):
    print(f"Warning: {message}", file=sys.stderr)


def _parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="sbom.py",
        description=(
            "Scan every git repository directly inside DIRECTORY for "
            f"{REQUIREMENTS_FILE} and {PACKAGE_JSON_FILE}, and save the dependencies "
            f"to {CSV_FILE} and {JSON_FILE} in DIRECTORY."
        ),
    )
    parser.add_argument("directory", help="directory containing the git repositories")
    return parser.parse_args(argv)


def run(argv):
    """Run the command line tool and return its exit code."""
    try:
        args = _parse_args(argv)
    except SystemExit as e:
        return EXIT_OK if e.code == 0 else EXIT_USAGE

    root = os.path.abspath(args.directory)
    if not os.path.exists(root):
        _error(f"'{root}' does not exist")
        return EXIT_ERROR
    if not os.path.isdir(root):
        _error(f"'{root}' is not a directory")
        return EXIT_ERROR

    try:
        repos = find_repos(root)
    except OSError as e:
        _error(f"could not read '{root}': {e.strerror}")
        return EXIT_ERROR

    if not repos:
        _error(f"no git repositories found in '{root}'")
        if os.path.exists(os.path.join(root, ".git")):
            print(
                f"'{root}' is itself a git repository. Pass the directory that contains "
                "your repositories instead.",
                file=sys.stderr,
            )
        return EXIT_ERROR

    print(f"Found {_plural(len(repos), 'repository', 'repositories')} in '{root}'")

    exit_code = EXIT_OK
    dependencies = []
    repositories = []
    for repo in repos:
        name = os.path.basename(repo)
        commit = git_commit(repo)
        try:
            files = find_dependency_files(repo)
            if not files:
                _warning(
                    f"no {REQUIREMENTS_FILE} or {PACKAGE_JSON_FILE} in '{repo}', skipping"
                )
                continue
            repo_dependencies = _scan_repo(repo, commit)
        except (OSError, DependencyFileError) as e:
            _error(f"skipping '{name}': {e}")
            exit_code = EXIT_ERROR
            continue
        dependencies.extend(repo_dependencies)
        repositories.append(
            {
                "name": name,
                "path": repo,
                "commit": commit,
                "files": files,
                "dependency_count": len(repo_dependencies),
            }
        )

    csv_path = os.path.join(root, CSV_FILE)
    json_path = os.path.join(root, JSON_FILE)
    try:
        write_csv(dependencies, csv_path)
        print(f"Saved SBOM in CSV format to '{csv_path}'")
        write_json(dependencies, json_path, root, repositories)
        print(f"Saved SBOM in JSON format to '{json_path}'")
    except OSError as e:
        _error(f"could not write SBOM: {e}")
        return EXIT_ERROR

    return exit_code


def main():
    sys.exit(run(sys.argv[1:]))


if __name__ == "__main__":
    main()
