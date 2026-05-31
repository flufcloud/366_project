# M4: Beta Release Report

Main Repo: [https://github.com/flufcloud/366\_project](https://github.com/flufcloud/366_project)  
Issue Board: [https://github.com/users/flufcloud/projects/2/views/1](https://github.com/users/flufcloud/projects/2/views/1)

## Executive Summary

This milestone delivers a beta-quality command-line security assistant for Linux (and WSL). The tool scans local repositories, produces Markdown security documentation, connects to GitHub to triage open issues and pull requests with LLM-assisted risk classification, and suggests mitigations. Security controls from earlier milestones (M2 requirements, M3 threat model) are implemented in code: credential storage, path confinement, extension allowlists, secret redaction, bounded LLM prompts, and user-facing errors without stack traces.

The beta is installable with `uv` from a locked dependency file, testable from the command line, and validated in GitHub Actions on every push and pull request.

---

## 1\. Development Environment Setup

### 1.1 Git / GitHub Repository

The project uses Git with a public GitHub repository: [https://github.com/flufcloud/366\_project](https://github.com/flufcloud/366_project)

Source layout follows a standard Python package structure:

| Path | Contents |
| :---- | :---- |
| `pyproject.toml`, `uv.lock` | Package metadata and locked dependencies |
| `src/secanalyzer/` | Application modules |
| `tests/` | pytest suite |
| `README.md`, `docs/guides/QUICKSTART.md` | Build, install, and run instructions |
| `docs/guides/SECURITY.md` | Vulnerability reporting and data handling policy |
| `docs/reports/TECHNICAL_REPORT.md` | Architecture and data flows |
| `docs/reports/SECURITY_REPORT.md` | Threats, mitigations, and code mapping |
| `AGENTS.md` | Developer/agent notes and phase checklist |

### 1.2 Issue Tracking

Issue tracking uses GitHub Projects (online): [https://github.com/users/flufcloud/projects/2/views/1](https://github.com/users/flufcloud/projects/2/views/1)

### 1.3 Build

This is a Python 3.11+ project. The build and dependency manager is `uv` (Astral), which fulfills the rubric's requirement for a reproducible build system (equivalent to Gradle, Bazel, or similar).

**Install from source:**

git clone https://github.com/flufcloud/366\_project.git

cd 366\_project

uv sync \--all-groups

This creates `.venv/` and installs all runtime and dev dependencies from the locked `uv.lock` file.

**Produce distributable artifacts:**

uv build

Output: wheels and sdist under `dist/`.

**Run without global install:**

uv run secanalyzer \--help

The console entry point `secanalyzer → secanalyzer.cli:main` is defined in `pyproject.toml`.

### 1.4 CI/CD

GitHub Actions workflow: `.github/workflows/ci.yml`

**Triggers:**

- Push to branches `main` or `master`  
- Pull request targeting `main` or `master`

**Pipeline steps (Ubuntu latest):**

| Step | Command |
| :---- | :---- |
| Checkout | `actions/checkout` |
| Install uv | `astral-sh/setup-uv@v5` (cached) |
| Install dependencies | `uv sync --frozen --all-groups` |
| Run tests | `uv run pytest` |
| Static security analysis | `uv run bandit -r src/secanalyzer` |
| Dependency CVE audit | `uv run pip-audit` |

A green Actions run is the gate for merge-ready changes. All pipeline commands can also be run locally for full parity with CI.

---

## 2\. Product Features

### 2.1 README: How to Build the System

`README.md` documents:

- **Prerequisites:** Linux or WSL2, Python 3.11+, `uv`, Git  
- **Development setup:** `uv sync --group dev`; run `pytest`, `bandit`, `pip-audit`  
- **Build:** `uv sync --all-groups`; `uv build`  
- **CI/CD:** Table of pipeline steps and link to the Actions tab

Because this is a Python project, "build" means a locked dependency sync plus optional wheel packaging via `uv build`, rather than a compiled-language compilation step.

### 2.2 README: How to Deploy and Run

The deployment model is a local CLI on the developer's machine. No server deployment is required. Please view the README.md and docs/guides/QUICKSTART.md that are attached in the appendix at the end of this report.

---

## 3\. Testing and Security

### 3.1 Unit Testing

**Test framework:** pytest (dev dependency group in `pyproject.toml`).

Test modules and their coverage scope:

| Test Module | Scope |
| :---- | :---- |
| `tests/test_cli.py` | CLI parsing, mutual exclusion, token flows |
| `tests/test_config.py` | `ConfigManager`, credential path handling |
| `tests/test_repo_analyzer.py` | Scan logic, allowlist enforcement, redaction, skip directories |
| `tests/test_repo_scan_inventory.py` | Repository inventory behavior |
| `tests/test_scan_llm.py` | LLM report orchestration (mocked HTTP) |
| `tests/test_scan_llm_quota.py` | Compaction, plain-text parsing, degraded report handling |
| `tests/test_llm.py` | LLM helpers, retries (429, 500), Gemma/Gemini compatibility |
| `tests/test_llm_scan.py` | LLM scan integration |
| `tests/test_github_client.py` | GitHub API client (mocked responses) |
| `tests/test_issues_session.py` | Issue session orchestration |
| `tests/test_package.py` | Package metadata smoke test |
| `tests/test_module_main.py` | `python -m secanalyzer` entry point |

Application modules under `src/secanalyzer/`: `cli.py`, `config.py`, `repo_analyzer.py`, `github_client.py`, `llm.py`, `scan_llm.py`, `issues_session.py`, `output.py`, `exceptions.py`, `main.py`.

**Run from the command line:**

uv run pytest

### 3.2 CI Integration of Tests

`pytest` is a required CI step; a failed test suite fails the build and blocks merge. `bandit` and `pip-audit` are also mandatory CI steps and will fail the workflow on reported findings (per current workflow configuration).

### 3.3 Static Analysis and Security Vulnerability Tracking

**Running bandit and pip-audit both result in no errors:**  
siddhu@siddhu:/mnt/c/Users/Sidd/Desktop/academic/366/366\_project$ uv run pip-audit  
No known vulnerabilities found  
Name        Skip Reason  
\----------- \--------------------------------------------------------------------------  
secanalyzer Dependency not found on PyPI and could not be audited: secanalyzer (0.1.0)  
siddhu@siddhu:/mnt/c/Users/Sidd/Desktop/academic/366/366\_project$ uv run bandit \-r src/secanalyzer  
\[main\]  INFO    profile include tests: None  
\[main\]  INFO    profile exclude tests: None  
\[main\]  INFO    cli include tests: None  
\[main\]  INFO    cli exclude tests: None  
\[main\]  INFO    running on Python 3.11.13  
Run started:2026-05-18 20:15:20.558515+00:00

Test results:  
        No issues identified.

Code scanned:  
        Total lines of code: 2730  
        Total lines skipped (\#nosec): 0

Run metrics:  
        Total issues (by severity):  
                Undefined: 0  
                Low: 0  
                Medium: 0  
                High: 0  
        Total issues (by confidence):  
                Undefined: 0  
                Low: 0  
                Medium: 0  
                High: 0  
Files skipped (0):  
---

