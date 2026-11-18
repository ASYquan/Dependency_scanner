# Dependency_scanner

A command line tool that scans a directory of git repositories for pip and npm
dependencies and saves a software bill of materials (SBOM) in CSV and JSON.

Requires Python 3.10 or newer. Only the standard library is used, so there is
nothing to install.

## Usage

```
$ python3 sbom.py /home/alice/code/repos/
Found 10 repositories in '/home/alice/code/repos'
Saved SBOM in CSV format to '/home/alice/code/repos/sbom.csv'
Saved SBOM in JSON format to '/home/alice/code/repos/sbom.json'
```

`python3 sbom.py --help` shows the usage.

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | SBOM saved |
| 1 | The directory doesn't exist, contains no git repositories, a dependency file couldn't be read, or the SBOM couldn't be written. When a single dependency file is broken, the SBOM is still saved without it. |
| 2 | Invalid command line arguments |

Errors and warnings are printed to stderr.

## Output

`sbom.csv` has one row per dependency:

| Column | Description |
|--------|-------------|
| `name` | Package name |
| `version` | Version as written in the file: `2.31.0` for `==2.31.0`, otherwise the specifier as is (`>=2.0`, `^18.2.0`). Empty if no version is given. |
| `type` | `pip` or `npm` |
| `path` | Absolute path to the `requirements.txt` or `package.json` it was found in |
| `scope` | `runtime`, or for npm the section it was listed in: `dev`, `optional`, `peer` |
| `purl` | [Package URL](https://github.com/package-url/purl-spec), e.g. `pkg:pypi/requests@2.31.0`. The version is only included when it is exact. |
| `repository` | Name of the repository directory |
| `commit` | Commit hash of the repository's HEAD, empty if unknown |

`sbom.json` contains the same entries under `dependencies`, together with when
the SBOM was generated, the scanned directory, and the repositories that were
included:

```json
{
  "generated_at": "2026-11-18T10:00:00Z",
  "tool": "sbom.py",
  "root": "/home/alice/code/repos",
  "repositories": [
    {
      "name": "cf-remote",
      "path": "/home/alice/code/repos/cf-remote",
      "commit": "bfb2f32184233e07806c842752fc5732a120b767",
      "files": ["/home/alice/code/repos/cf-remote/requirements.txt"],
      "dependency_count": 1
    }
  ],
  "dependencies": [
    {
      "name": "cryptography",
      "version": "42.0.5",
      "type": "pip",
      "path": "/home/alice/code/repos/cf-remote/requirements.txt",
      "scope": "runtime",
      "purl": "pkg:pypi/cryptography@42.0.5",
      "repository": "cf-remote",
      "commit": "bfb2f32184233e07806c842752fc5732a120b767"
    }
  ]
}
```

## Project layout

- `sbom.py`: command line tool. Finds the repositories, reads the git commit and writes the CSV and JSON files.
- `dependency_reader.py`: parses `requirements.txt` and `package.json` for a single repository.
- `tests.py`: tests, run with `python -m pytest tests.py -v`. They also run in CI on every pull request.

## Assumptions

- Only the immediate subdirectories of the given directory are scanned. A subdirectory counts as a git repository if it contains `.git`, either a directory or a file (worktrees and submodules).
- Only `requirements.txt` and `package.json` in the top level of each repository are read.
- A repository with neither file is skipped with a warning instead of failing the whole run.
- Lines in `requirements.txt` that aren't package requirements are skipped: options such as `-r`, `-e`, `--index-url`, and URLs, VCS links and local paths without a package name. Extras and environment markers are removed (`requests[socks]; python_version>"3.8"` becomes `requests`).
- From `package.json`, `dependencies`, `devDependencies`, `optionalDependencies` and `peerDependencies` are included, so the same package can appear more than once with different scopes.
- The git commit is read from the files in `.git` (`HEAD`, loose refs and `packed-refs`) rather than by running `git`.
- Existing `sbom.csv` and `sbom.json` files in the directory are overwritten.

## Known issues

- Files included with `-r` / `-c` in `requirements.txt` are not followed.
- Versions are the specifiers from the dependency files, not the versions that are actually installed. A range such as `>=2.0` is not resolved.
- Indirect dependencies (from `package-lock.json` or pip's dependency resolution) are not included.
- Repositories nested deeper than one level, and dependency files in subdirectories (monorepos), are not found.
- Other dependency files (`pyproject.toml`, `setup.py`, `Pipfile`, `yarn.lock`, ...) are not supported.
- Symlinked directories are followed, so a repository linked twice is listed twice.

## Ideas for next features

- Read `package-lock.json` to include indirect npm dependencies, with the exact installed versions.
- Support `pyproject.toml`, `Pipfile.lock`, `poetry.lock` and `yarn.lock`.
- Look up known vulnerabilities for each dependency, for example in the OSV or NVD database.
- Compare two SBOMs to show which dependencies were added, removed or upgraded.
- Search the SBOM: "which repositories use libawesomejson 1.2.3?"
- Recursive scanning with a configurable depth.
- License information for each dependency.

