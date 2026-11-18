"""Read pip and npm dependencies from a single source code repository.

Looks for requirements.txt and package.json in the top level of the repository
and returns one record per dependency.
"""

import json
import os

REQUIREMENTS_FILE = "requirements.txt"
PACKAGE_JSON_FILE = "package.json"

# package.json section -> scope written to the SBOM
NPM_SECTIONS = (
    ("dependencies", "runtime"),
    ("devDependencies", "dev"),
    ("optionalDependencies", "optional"),
    ("peerDependencies", "peer"),
)

VERSION_OPERATOR_CHARS = "=<>!~("


class DependencyFileError(Exception):
    """A dependency file exists but could not be read or parsed."""


def find_dependency_files(repo_path):
    """Return absolute paths of the dependency files in the top level of repo_path."""
    repo_path = os.path.abspath(repo_path)
    if not os.path.isdir(repo_path):
        raise NotADirectoryError(f"'{repo_path}' is not a directory")

    found = []
    for filename in (REQUIREMENTS_FILE, PACKAGE_JSON_FILE):
        path = os.path.join(repo_path, filename)
        if os.path.isfile(path):
            found.append(path)
    return found


def read_repo(repo_path):
    """Return all dependencies found in repo_path, from every supported file."""
    repo_path = os.path.abspath(repo_path)
    repository = os.path.basename(repo_path.rstrip(os.sep))

    dependencies = []
    for path in find_dependency_files(repo_path):
        if os.path.basename(path) == REQUIREMENTS_FILE:
            dependencies.extend(parse_requirements(path))
        else:
            dependencies.extend(parse_package_json(path))

    for dep in dependencies:
        dep["repository"] = repository
    return dependencies


# --- requirements.txt -------------------------------------------------------


def parse_requirements(path):
    """Parse a pip requirements.txt file."""
    path = os.path.abspath(path)
    text = _read_text(path)

    dependencies = []
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
                "path": path,
                "purl": _pypi_purl(name, spec),
            }
        )
    return dependencies


def _join_continued_lines(text):
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


def _strip_comment(line):
    # pip only treats '#' as a comment at the start of a line or after
    # whitespace, so URL fragments like '#egg=name' are left alone.
    for i, char in enumerate(line):
        if char == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i]
    return line


def _parse_requirement_line(line):
    """Return (name, version_spec) for a requirement line, or None to skip it."""
    line = _strip_comment(line).strip()

    # Options such as -r, -e, -c, --index-url are not dependencies.
    if not line or line.startswith("-"):
        return None

    # Per-requirement options, e.g. 'pkg==1.0 --hash=sha256:...'
    option_start = line.find(" --")
    if option_start != -1:
        line = line[:option_start]

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


def _pinned_pip_version(spec):
    """Return the exact version if spec is a single '==X' pin, otherwise None."""
    if not spec.startswith("==") or spec.startswith("==="):
        return None
    version = spec[2:]
    if not version or "," in version or "*" in version:
        return None
    return version


def _pip_version(spec):
    pinned = _pinned_pip_version(spec)
    return pinned if pinned is not None else spec


def _pypi_purl(name, spec):
    # PEP 503 normalisation: lowercase, runs of '-', '_' and '.' become '-'
    normalized = []
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


def parse_package_json(path):
    """Parse the dependency sections of an npm package.json file."""
    path = os.path.abspath(path)
    text = _read_text(path)

    try:
        data = json.loads(text)
    except ValueError as e:
        raise DependencyFileError(f"'{path}' is not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise DependencyFileError(f"'{path}' does not contain a JSON object")

    dependencies = []
    for section, scope in NPM_SECTIONS:
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue
        for name, spec in entries.items():
            spec = spec if isinstance(spec, str) else str(spec)
            dependencies.append(
                {
                    "name": name,
                    "version": spec,
                    "type": "npm",
                    "scope": scope,
                    "path": path,
                    "purl": _npm_purl(name, spec),
                }
            )
    return dependencies


def _exact_npm_version(spec):
    """Return spec without a leading '=' or 'v' if it is an exact x.y.z version."""
    version = spec.strip().lstrip("=v")
    core = version.split("+", 1)[0].split("-", 1)[0]
    parts = core.split(".")
    if len(parts) == 3 and all(part.isdigit() for part in parts):
        return version
    return None


def _npm_purl(name, spec):
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


def _read_text(path):
    try:
        with open(path, encoding="utf-8-sig") as f:
            return f.read()
    except UnicodeDecodeError as e:
        raise DependencyFileError(f"'{path}' is not valid UTF-8 text") from e
    except OSError as e:
        raise DependencyFileError(f"could not read '{path}': {e.strerror}") from e


def _purl_encode(value):
    safe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_~"
    encoded = []
    for char in value:
        if char in safe:
            encoded.append(char)
        else:
            encoded.extend(f"%{byte:02X}" for byte in char.encode("utf-8"))
    return "".join(encoded)
