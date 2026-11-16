---
name: code-style
description: Format and organize BridgePatcher source code and files to match the coding style of Dortania's upstream OpenCore Legacy Patcher, without changing behavior or bringing back upstream names.
---

# Code Style Skill

## Purpose

Apply the coding style documented in this file to BridgePatcher code and files. The result should
look natural beside code in Dortania's OpenCore Legacy Patcher, which BridgePatcher is based on, so
upstream fixes stay easy to port.

This skill complements `AGENTS.md`. Where the two disagree, `AGENTS.md` wins.

## 1. Non-negotiable rules

1. Preserve behavior. A style-only pass must not change algorithms, control flow, data, public interfaces, side effects, error handling, or compatibility.
2. Follow this coding style, not generic style preferences. Do not blindly apply PEP 8, Black, `ruff format`, Google's style guide, or another formatter when it conflicts with the conventions documented here.
3. Treat the examples as a style fingerprint, not a command to reproduce every irregularity. The upstream code contains legacy code and inconsistencies. Prefer repeated, clear patterns over isolated quirks.
4. Match the language and role of the file. Python conventions do not automatically apply to shell scripts, plist files, JSON, YAML, XML, Markdown, or other languages.
5. Keep edits focused. Do not refactor, rename symbols, modernize APIs, redesign architecture, or fix unrelated bugs unless the user explicitly asks. Do not reformat code you were not asked to touch (see `AGENTS.md` section 1).
6. Never silently make a functional change under the label of formatting.
7. Do not claim tests, validation, or linting passed unless they were actually run.
8. Style follows upstream, names do not. Never bring back upstream names or identifiers (the upstream app name or its abbreviation, `com.dortania.*`, Dortania folders, old NVRAM keys or plist names). Use the BridgePatcher equivalents: the `bridgepatcher` package, `BridgePatcher-*` NVRAM keys, `BridgePatcher.plist`, the project's own folders. Old names may only appear in code that detects, migrates or cleans up legacy installs, marked as described in `.github/scripts/branding_check.py`.

## 2. Python style reference

### 2.1 At a glance

- Four spaces for indentation.
- Double quotes are common for strings.
- Module docstrings commonly start with a short filename-and-purpose summary.
- Imports are grouped into standard-library, third-party, and project-local sections, with blank lines between groups. The exact ordering within groups is not perfectly consistent; prioritize the closest matching file.
- Relative imports are used within the `bridgepatcher` package.
- Type annotations are used, but not universally. Annotate in the style of the surrounding module rather than forcing annotations onto every existing function.
- `pathlib.Path` is used for path-oriented code in many newer/maintained modules.
- Classes and functions commonly use short descriptive docstrings.
- Comments often use concise sentence fragments or short explanatory sentences.
- Section comments are common for grouping related initialization/configuration work.
- Blank lines separate logical phases and class methods. Some files intentionally use two blank lines between methods.
- Logging through Python's `logging` module is common in operational code.
- Existing compatibility behavior and macOS-specific workarounds are important; do not remove them as cleanup.

### 2.2 Indentation and whitespace

Use four spaces per indentation level. Do not use tabs for Python indentation.

Use blank lines to separate:

- Module docstring from imports.
- Import groups.
- Top-level classes and functions.
- Logical sections within functions.
- Class methods.

Upstream code frequently uses two blank lines between class methods and top-level definitions. Match the surrounding file; do not mechanically add blank lines inside expressions or data structures.

Some files align assignment operators and type annotations vertically in related blocks, as in `bridgepatcher/constants.py`:

```python
APP_NAME:                  str = "BridgePatcher"
APP_BUNDLE_NAME:           str = f"{APP_NAME}.app"
APP_EXECUTABLE_NAME:       str = APP_NAME
```

The same file also aligns `import` keywords:

```python
from pathlib   import Path
from typing    import Optional
from packaging import version
```

This alignment is a recognizable pattern in some constants/data sections, but it is not universal. Use it only when the nearby code clearly uses aligned declarations. Keep the alignment intact when adding a line to such a block. Do not introduce large amounts of padding into ordinary assignments.

### 2.3 Imports

Follow the nearby file's import style. A common grouping pattern is:

```python
import logging
import plistlib
import subprocess

from pathlib import Path

from . import utilities
from .. import constants
```

The code does not enforce one perfectly consistent alphabetical ordering. Do not reorder imports aggressively if doing so would create a large unrelated diff or risk changing import behavior.

Keep standard-library, third-party, and local project imports visually separated. Relative imports are appropriate for package-internal imports when consistent with the module.

Do not add imports that are not needed. Do not add new third-party dependencies without asking.

### 2.4 Module docstrings

A common module header is a triple-double-quoted summary with the filename and purpose:

```python
"""
constants.py: Defines versioning, file paths and other settings for the patcher
"""
```

Another example:

```python
"""
build.py: Class for generating OpenCore Configurations tailored for Macs
"""
```

Use this compact form for straightforward modules. Longer modules may include additional explanatory text or usage information when appropriate. Do not invent lengthy boilerplate for a small file.

### 2.5 Naming

Follow established Python naming where it is clear, while preserving existing names and APIs.

Observed patterns include:

- `PascalCase` for many classes, e.g. `BuildOpenCore`.
- `snake_case` for functions and methods, e.g. `generate_copy_arguments`.
- `snake_case` for variables and attributes, e.g. `build_path`.
- `UPPER_SNAKE_CASE` for module-level constants, e.g. `APP_NAME`.
- Lowercase names for some legacy classes and enums, e.g. `disk_installation`, `os_data`, and `os_conversion`.

Important: the code contains legacy naming that does not follow modern Python conventions. Do not rename existing classes, methods, enum members, fields, or public symbols just to make them conform to a generic naming standard. For new code, prefer the closest local precedent. Constants that hold pre-rename identifiers use a `LEGACY_` prefix (e.g. `LEGACY_APP_NAME`).

Private/internal methods may use a leading underscore, as in `_build_efi` and `_generate_base`.

### 2.6 Type annotations

Annotations are used selectively. Examples include:

```python
def _build_efi(self) -> None:
    ...

def generate_copy_arguments(source: str, destination: str) -> list:
    ...

self.constants: constants.Constants = versions
```

Use annotations when:

- The surrounding module uses them.
- They improve clarity.
- The type is clear from the code or existing project definitions.

The project runs on Python 3.13 (`ruff.toml`: `target-version = "py313"`), so newer syntax is technically available. Still, do not rewrite existing annotations (e.g. `Optional[str]` to `str | None`) during a style pass; match the surrounding module.

Do not force annotations onto every legacy function. Do not add annotations that are inaccurate or speculative.

### 2.7 Docstrings and comments

Use triple-double-quoted docstrings. Keep simple function docstrings concise:

```python
def can_copy_on_write(source: str, destination: str) -> bool:
    """
    Check if Copy on Write is supported between source and destination
    """
```

Longer documented functions may use sections such as `Parameters:` and `Returns:` with indented descriptions:

```python
def os_to_kernel(os: str) -> int:
    """
    Convert OS version to major XNU version

    Parameters:
        os (str): OS version

    Returns:
        int: Major XNU version
    """
```

Use comments to explain intent, compatibility constraints, non-obvious decisions, or logical sections. Short section comments are common:

```python
# Patcher Versioning
# URLs
# OpenCore Versioning
```

Keep comments accurate when moving or editing code. Do not remove comments that explain hardware quirks, macOS-version compatibility, firmware behavior, T2/T1 specifics, or workarounds. Do not remove `branding: legacy` / `branding: keep` markers.

Do not add redundant comments that merely restate the next line.

### 2.8 Strings and expressions

Double quotes are common:

```python
logging.info("Creating build folder")
```

f-strings are common for interpolation:

```python
logging.info(f"Building Configuration for {self.model}")
```

Use readable multiline expressions when they are needed. Preserve the expression's exact semantics and evaluation order.

`Path` is used for filesystem operations in many modules:

```python
if not Path(source).exists():
    raise FileNotFoundError(f"Source file not found: {source}")
```

When formatting existing path code, do not change path semantics, symlink behavior, exception behavior, or platform-specific handling.

### 2.9 Classes and methods

Use the local module's class organization. Upstream-style classes commonly:

- Place a class docstring immediately inside the class.
- Define `__init__` near the top.
- Store dependencies/configuration on `self`.
- Use helper methods for logically distinct phases.
- Use leading underscores for internal helpers in many newer modules.
- Keep methods separated with blank lines.

Example shape:

```python
class BuildOpenCore:
    """
    Core Build Library for generating and validating OpenCore EFI Configurations
    compatible with genuine Macs
    """

    def __init__(self, model: str, global_constants: constants.Constants) -> None:
        self.model: str = model
        self.constants: constants.Constants = global_constants

        self._build_opencore()

    def _build_efi(self) -> None:
        """
        Build EFI folder
        """
        ...
```

This is a structural illustration, not a requirement to rename or redesign an existing class.

### 2.10 Logging, exceptions, compatibility and security

Operational modules commonly use `logging.info(...)` and related logging calls. Preserve the existing logging approach and message meaning.

Preserve exception types, exception boundaries, fallback behavior, and compatibility branches. The code contains explicit branches for different macOS generations and hardware situations (including T2/T1 Macs). These are functional requirements, not stylistic clutter.

Do not replace a broad exception handler, subprocess call, fallback, or compatibility workaround as part of a formatting-only pass. If something looks unsafe or incorrect (see `AGENTS.md` section 5), report it separately instead of fixing it silently.

Areas kept on Dortania's upstream state (GPU, wireless, audio root patches, etc.) should not be reformatted at all unless the user explicitly asks; a style diff there makes porting upstream changes harder.

## 3. Lint configuration

The repository's `.flake8`:

```ini
[flake8]
extend-ignore = E501, E203
per-file-ignores =
    Resources/constants.py:E704
```

The repository's `.pylintrc`:

```ini
[MASTER]
init-hook="from pylint.config import find_pylintrc; import os, sys; sys.path.append(os.path.dirname(find_pylintrc()))"

[MESSAGES CONTROL]
disable=unused-import,
        subprocess-run-check,
        line-too-long,
        too-few-public-methods,
        missing-module-docstring,
        missing-class-docstring,
        missing-function-docstring
```

The repository's `ruff.toml` sets `target-version = "py313"`.

These files may change; read the current versions when it matters. The ignored checks describe the configured lint behavior, not permission to disregard readability.

Notable consequences:

- `E501` (line length) is ignored. Do not force arbitrary line wrapping when it makes code less consistent with the surrounding code.
- `E203` is ignored.
- Pylint disables unused imports, subprocess-run-check, line-too-long, too-few-public-methods, and missing docstrings.
- `ruff check` is used as a linter. Do not run `ruff format` over files; it would reformat code against the conventions above.

## 4. Other languages and file types

The reference above is strongest for Python. It does **not** establish a complete style guide for every language in the repository.

When a file is not Python:

1. Identify its language and file role.
2. Use the closest matching files in this repository (or upstream) as the local reference.
3. Preserve the file's existing schema, semantics, ordering requirements, and compatibility.
4. Use the least opinionated formatting consistent with the file.
5. Do not claim that a convention is a project-wide rule unless there is evidence for it.

Specific precautions:

- **Shell / `.command`:** Preserve shebangs, quoting, exit status behavior, environment handling, and command order.
- **Plist/XML:** Preserve key names, value types, nesting, required ordering, and macOS-specific semantics. `.github/scripts/check_plist_format.py` checks plist formatting.
- **JSON/YAML:** Preserve data types, keys, anchors, comments where supported, and schema requirements.
- **Markdown:** Preserve links, code fences, heading hierarchy, and document intent.
- **CI workflows, licence/credit files, release scripts, payloads:** do not touch without an explicit request (`AGENTS.md` section 3).
- **Generated or vendored code:** Do not reformat automatically. Ask or explain before changing it.
- **Binary files:** Never attempt text formatting.

If no relevant example is available, state that the style is inferred from the file itself.

## 5. Formatting workflow

### Step 1 - Inspect

- Inventory all supplied files and snippets.
- Identify languages, file roles, and scope.
- Identify generated, vendored, or binary files, and areas kept on upstream state.
- Read enough surrounding code to understand local conventions.
- If only a snippet is supplied, preserve its context and avoid inventing surrounding architecture.

### Step 2 - Select conventions

- Apply the Python profile above to Python.
- For other languages, use actual nearby project examples.
- Resolve conflicts in this order: behavior and compatibility; `AGENTS.md`; closest local precedent; upstream conventions; conservative readability.
- If the source itself is inconsistent, choose the clearest repeated pattern and avoid gratuitous normalization.

### Step 3 - Format

Apply only relevant changes to:

- Indentation and whitespace.
- Blank lines and line breaks.
- Imports and declaration layout.
- Comments and docstrings.
- Type annotation formatting.
- Function/class/module organization.
- String, collection, and expression formatting.

Do not change names, signatures, defaults, values, algorithms, control flow, or interfaces unless the user explicitly requests a broader code change.

### Step 4 - Validate

Run what applies to the changed files (see `AGENTS.md` section 6):

- `python3 .github/scripts/check_python.py --root .`
- `ruff check .`
- `python3 .github/scripts/branding_check.py`
- `python3 .github/scripts/check_security.py --root . --json "$(mktemp)"` (needs `bandit`) when code changed beyond whitespace.
- Validate structured data with an appropriate parser.
- Review the diff for unintended semantic changes and confirm only intended files were changed.

Never claim validation that was not performed. Do not install dependencies, modify system configuration, or run destructive commands merely to format code.

### Step 5 - Report

Briefly report:

- Which files were formatted.
- Which conventions were applied.
- Any conventions that were uncertain or unavailable.
- Which validation checks were actually run and their results.
- Any functional or security concerns noticed but deliberately not changed.

If the code already matches the style, say so. If only some changes were safe, explain what was left untouched.

## 6. Interaction rules

- If the user supplies code and asks for formatting, proceed; do not ask them to repeat the style requirements.
- Ask one focused question only when an ambiguity materially affects the result.
- For a whole project, inventory first and work in a controlled, staged way. Avoid indiscriminate rewrites.
- Preserve original files unless in-place modification is clearly requested. If creating separate outputs, clearly identify the formatted copies.
- Do not claim affiliation with Dortania or imply official endorsement.

## Guiding principle

**Match Dortania's upstream style, keep BridgePatcher's own names, preserve the code's behavior, and never mistake a formatting pass for permission to refactor.**
