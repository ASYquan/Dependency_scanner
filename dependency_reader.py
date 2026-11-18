"""Read pip and npm dependencies from a single source code repository.

Looks for requirements.txt and package.json in the top level of the repository
and returns one record per dependency. If package-lock.json is present next to
package.json, the indirect npm dependencies are read from it as well.
"""

import json
import os
import re
from collections.abc import Collection, Iterator
from typing import Any

REQUIREMENTS_FILE = "requirements.txt"
PACKAGE_JSON_FILE = "package.json"
PACKAGE_LOCK_FILE = "package-lock.json"

# package.json section -> scope written to the SBOM
NPM_SECTIONS: tuple[tuple[str, str], ...] = (
    ("dependencies", "runtime"),
    ("devDependencies", "dev"),
    ("optionalDependencies", "optional"),
    ("peerDependencies", "peer"),
)

VERSION_OPERATOR_CHARS = "=<>!~("

# A dependency record: name, version, type, scope, relationship, path, purl
# and repository
Dependency = dict[str, str]
StrPath = str | os.PathLike[str]


class DependencyFileError(Exception):
    """A dependency file exists but could not be read or parsed."""


def find_dependency_files(repo_path: StrPath) -> list[str]:
    """Return absolute paths of the dependency files in the top level of repo_path.

    package-lock.json is only included when package.json is there too.
    """
    repo_path = os.path.abspath(repo_path)
    if not os.path.isdir(repo_path):
        raise NotADirectoryError(f"'{repo_path}' is not a directory")

    found: list[str] = []
    for filename in (REQUIREMENTS_FILE, PACKAGE_JSON_FILE):
        path = os.path.join(repo_path, filename)
        if os.path.isfile(path):
            found.append(path)
    lock = os.path.join(repo_path, PACKAGE_LOCK_FILE)
    if os.path.join(repo_path, PACKAGE_JSON_FILE) in found and os.path.isfile(lock):
        found.append(lock)
    return found


def read_repo(repo_path: StrPath) -> list[Dependency]:
    """Return all dependencies found in repo_path, from every supported file."""
    repo_path = os.path.abspath(repo_path)
    repository = os.path.basename(repo_path.rstrip(os.sep))

    dependencies: list[Dependency] = []
    direct_npm: set[str] = set()
    for path in find_dependency_files(repo_path):
        filename = os.path.basename(path)
        if filename == REQUIREMENTS_FILE:
            dependencies.extend(parse_requirements(path))
        elif filename == PACKAGE_JSON_FILE:
            npm = parse_package_json(path)
            direct_npm.update(dep["name"] for dep in npm)
            dependencies.extend(npm)
        else:
            dependencies.extend(parse_package_lock(path, direct_npm))

    for dep in dependencies:
        dep["repository"] = repository
    return dependencies


# --- requirements.txt -------------------------------------------------------


def parse_requirements(path: StrPath) -> list[Dependency]:
    """Parse a pip requirements.txt file."""
    path = os.path.abspath(path)
    text = _read_text(path)

    dependencies: list[Dependency] = []
    for line in _join_continued_lines(text):
        parsed = _parse_requirement_line(line)
        if parsed is None:
            continue
        name, spec = parsed
        dependencies.append(
            {
                "name": name,
                "version": _pip_version(spec),
                "type": "pip",
                "scope": "runtime",
                "relationship": "direct",
                "path": path,
                "purl": _pypi_purl(name, spec),
            }
        )
    return dependencies


def _join_continued_lines(text: str) -> Iterator[str]:
    """Yield logical lines, joining lines that end with a backslash."""
    pending = ""
    for raw in text.splitlines():
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        yield pending + raw
        pending = ""
    if pending:
        yield pending


def _strip_comment(line: str) -> str:
    """Remove a trailing '# comment' from a requirements line."""
    # pip only treats '#' as a comment at the start of a line or after
    # whitespace, so URL fragments like '#egg=name' are left alone.
    for i, char in enumerate(line):
        if char == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i]
    return line


def _parse_requirement_line(line: str) -> tuple[str, str] | None:
    """Return (name, version_spec) for a requirement line, or None to skip it."""
    line = _strip_comment(line).strip()

    # Options such as -r, -e, -c, --index-url are not dependencies.
    if not line or line.startswith("-"):
        return None

    # Per-requirement options, e.g. 'pkg==1.0 --hash=sha256:...'
    option = re.search(r"\s--", line)
    if option:
        line = line[: option.start()]

    # Environment markers, e.g. 'pywin32==306; sys_platform == "win32"'
    line = line.split(";", 1)[0].strip()

    end = 0
    while end < len(line) and (line[end].isalnum() or line[end] in "._-"):
        end += 1
    name = line[:end]
    rest = line[end:].strip()

    if not name or not name[0].isalnum():
        return None
    # Bare URLs, VCS links and local paths (git+https://..., ./pkg, C:\pkg)
    if rest and rest[0] not in "[@" + VERSION_OPERATOR_CHARS:
        return None
    # Local archives such as 'pkg-1.0-py3-none-any.whl'
    if name.endswith((".whl", ".zip", ".tar.gz", ".tgz")):
        return None

    if rest.startswith("["):
        close = rest.find("]")
        if close == -1:
            return None
        rest = rest[close + 1 :].strip()
    if rest.startswith("@"):
        return name, rest[1:].strip()

    spec = "".join(rest.split())
    if spec.startswith("(") and spec.endswith(")"):
        spec = spec[1:-1]
    return name, spec


def _pinned_pip_version(spec: str) -> str | None:
    """Return the exact version if spec is a single '==X' pin, otherwise None."""
    if not spec.startswith("==") or spec.startswith("==="):
        return None
    version = spec[2:]
    if not version or "," in version or "*" in version:
        return None
    return version


def _pip_version(spec: str) -> str:
    """Return the pinned version, or the spec as written if it isn't pinned."""
    pinned = _pinned_pip_version(spec)
    return pinned if pinned is not None else spec


def _pypi_purl(name: str, spec: str) -> str:
    """Return the package URL of a PyPI package (version only if pinned)."""
    # PEP 503 normalisation: lowercase, runs of '-', '_' and '.' become '-'
    normalized: list[str] = []
    for char in name.lower():
        if char in "-_.":
            if not normalized or normalized[-1] != "-":
                normalized.append("-")
        else:
            normalized.append(char)
    purl = "pkg:pypi/" + _purl_encode("".join(normalized))

    pinned = _pinned_pip_version(spec)
    if pinned is not None:
        purl += "@" + _purl_encode(pinned)
    return purl


# --- package.json -----------------------------------------------------------


def parse_package_json(path: StrPath) -> list[Dependency]:
    """Parse the dependency sections of an npm package.json file."""
    path = os.path.abspath(path)
    data = _read_json_object(path)

    dependencies: list[Dependency] = []
    for section, scope in NPM_SECTIONS:
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue
        for name, spec in entries.items():
            # npm versions are strings; show anything else as it's written in the file
            spec = spec if isinstance(spec, str) else json.dumps(spec)
            dependencies.append(
                {
                    "name": name,
                    "version": spec,
                    "type": "npm",
                    "scope": scope,
                    "relationship": "direct",
                    "path": path,
                    "purl": _npm_purl(name, spec),
                }
            )
    return dependencies


def parse_package_lock(path: StrPath, direct: Collection[str]) -> list[Dependency]:
    """Return the indirect dependencies recorded in an npm package-lock.json.

    direct holds the package names from package.json. Those are skipped at the
    top level because package.json already lists them; copies installed deeper
    in the tree are indirect and included. Identical entries are listed once.
    """
    path = os.path.abspath(path)
    data = _read_json_object(path)

    dependencies: list[Dependency] = []
    seen: set[tuple[str, str, str]] = set()
    for name, info, top_level in _lock_entries(data):
        if top_level and name in direct:
            continue
        version = info.get("version")
        version = version if isinstance(version, str) else ""
        scope = _lock_scope(info)
        if (name, version, scope) in seen:
            continue
        seen.add((name, version, scope))
        dependencies.append(
            {
                "name": name,
                "version": version,
                "type": "npm",
                "scope": scope,
                "relationship": "indirect",
                "path": path,
                "purl": _npm_purl(name, version),
            }
        )
    return dependencies


def _lock_entries(data: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any], bool]]:
    """Yield (name, entry, is_top_level) for every package in a lock file."""
    packages = data.get("packages")
    if isinstance(packages, dict):
        yield from _lock_entries_flat(packages)
    elif isinstance(data.get("dependencies"), dict):
        yield from _lock_entries_nested(data["dependencies"])


def _lock_entries_flat(
    packages: dict[str, Any],
) -> Iterator[tuple[str, dict[str, Any], bool]]:
    """Read lockfileVersion 2 and 3: a flat map from install location to package.

    Locations look like 'node_modules/a/node_modules/b'; "" is the project itself.
    """
    for location, info in packages.items():
        if "node_modules/" not in location or not isinstance(info, dict):
            continue
        if info.get("link"):  # a local folder, not an installed package
            continue
        name = location.rsplit("node_modules/", 1)[1]
        yield name, info, location == "node_modules/" + name


def _lock_entries_nested(
    tree: dict[str, Any],
) -> Iterator[tuple[str, dict[str, Any], bool]]:
    """Read lockfileVersion 1 (npm 6 and older): a nested "dependencies" tree.

    Walked with a list instead of recursion so a deep tree can't crash it.
    """
    pending = [(tree, True)]
    while pending:
        entries, top_level = pending.pop(0)
        for name, info in entries.items():
            if not isinstance(info, dict):
                continue
            yield name, info, top_level
            nested = info.get("dependencies")
            if isinstance(nested, dict):
                pending.append((nested, False))


def _lock_scope(info: dict[str, Any]) -> str:
    """Return the scope of a lock file entry from its dev/optional/peer flags."""
    if info.get("dev") or info.get("devOptional"):
        return "dev"
    if info.get("optional"):
        return "optional"
    if info.get("peer"):
        return "peer"
    return "runtime"


def _exact_npm_version(spec: str) -> str | None:
    """Return spec without a leading '=' or 'v' if it is an exact x.y.z version."""
    version = spec.strip().lstrip("=v")
    core = version.split("+", 1)[0].split("-", 1)[0]
    parts = core.split(".")
    if len(parts) == 3 and all(part.isascii() and part.isdigit() for part in parts):
        return version
    return None


def _npm_purl(name: str, spec: str) -> str:
    """Return the package URL of an npm package (version only if exact)."""
    if name.startswith("@") and "/" in name:
        scope, package = name[1:].split("/", 1)
        purl = "pkg:npm/%40" + _purl_encode(scope) + "/" + _purl_encode(package)
    else:
        purl = "pkg:npm/" + _purl_encode(name)

    exact = _exact_npm_version(spec)
    if exact is not None:
        purl += "@" + _purl_encode(exact)
    return purl


# --- helpers ----------------------------------------------------------------


def _read_json_object(path: str) -> dict[str, Any]:
    """Return the JSON object in a file, or raise DependencyFileError."""
    text = _read_text(path)
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as e:
        # RecursionError: nested too deeply to parse, e.g. '[[[[...'
        raise DependencyFileError(f"'{path}' is not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise DependencyFileError(f"'{path}' does not contain a JSON object")
    return data


def _read_text(path: str) -> str:
    """Return the contents of a text file, or raise DependencyFileError."""
    try:
        with open(path, encoding="utf-8-sig") as f:
            return f.read()
    except UnicodeDecodeError as e:
        raise DependencyFileError(f"'{path}' is not valid UTF-8 text") from e
    except OSError as e:
        raise DependencyFileError(f"could not read '{path}': {e.strerror}") from e


def _purl_encode(value: str) -> str:
    """Percent-encode value for use in a package URL."""
    safe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_~"
    encoded: list[str] = []
    for char in value:
        if char in safe:
            encoded.append(char)
        else:
            encoded.extend(f"%{byte:02X}" for byte in char.encode("utf-8"))
    return "".join(encoded)
