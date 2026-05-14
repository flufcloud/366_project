# AI-Powered Codebase Security Analyzer

A local Linux command-line tool that uses large language models to help developers and security engineers understand, document, and evaluate the security posture of a codebase.

Point the tool at any repository and it will automatically generate structured documentation of the codebase's architecture and data flow, fetch open GitHub issues and pull requests, classify each item by security risk level (low / medium / high), and propose preliminary root causes and suggested fixes — all without ever leaving your machine beyond the API calls you explicitly authorize.

---

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Development with UV (WSL / Linux)](#development-with-uv-wsl--linux)
- [Building from Source](#building-from-source)
- [Installation](#installation)
- [CI/CD](#cicd)
- [Token Setup](#token-setup)
- [Quickstart](#quickstart)
- [Quickstart guide (step-by-step)](QUICKSTART.md)
- [CLI Reference](#cli-reference)
- [Security and Data Handling](#security-and-data-handling)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

---

## Features

| Feature | Description |
|---|---|
| **Codebase Documentation Engine** | Recursively scans a repository and emits Markdown (file index, redacted snippets, and security notes). Narrative enrichment via LLM may be added later. |
| **Issue & PR Analyzer** | Authenticates with GitHub, presents an interactive menu of open issues and PRs, and classifies each item's security risk with a justification. |
| **Preliminary Solutions** | For every flagged issue or PR, generates a plain-language suggested fix or direction of investigation. |
| **Multi-LLM Support** | Choose your own LLM backend — Claude, Gemini, and others are supported. |
| **Security-First Design** | Secrets are redacted before any data is sent to an LLM. Credentials are never logged or printed to stdout. |

---

## Prerequisites

- **OS:** Linux (Ubuntu 20.04+ or Debian 11+ recommended), or **WSL2** on Windows for the same workflow
- **Python:** 3.11 or higher (see [`.python-version`](.python-version))
- **[uv](https://docs.astral.sh/uv/)** 0.5+ (recommended installer and lockfile manager for this repo)
- **Git:** Any recent version
- A **GitHub Personal Access Token** with `repo` scope (for `--issues`)
- An API key for your chosen LLM provider (**Claude** / **Gemini**) for `--issues`

Verify Python (after `uv` has installed the project interpreter):

```bash
uv run python --version
```

---

## Development with UV (WSL / Linux)

The canonical dev workflow keeps Python and dependencies **inside this repository** via [uv](https://docs.astral.sh/uv/). From the repo root (in WSL, paths look like `/mnt/c/.../366_project`):

```bash
uv sync --group dev
uv run pytest
uv run bandit -r src/secanalyzer
uv run pip-audit
uv run secanalyzer --help
```

Agent-oriented checklists and phase notes live in [AGENTS.md](AGENTS.md).

---

## Building from Source

The package is defined in [`pyproject.toml`](pyproject.toml) (setuptools backend). With **uv**:

```bash
uv sync --all-groups
uv build
```

Wheels and sdist are written to `dist/`. Install into the active environment with `uv pip install dist/secanalyzer-*.whl`, or continue using `uv run secanalyzer` from the project root without a separate install step.

---

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/flufcloud/366_project.git
   cd 366_project
   ```

2. **Install dependencies and the `secanalyzer` package into a project-local venv** (recommended):

   ```bash
   uv sync --all-groups
   ```

   This creates `.venv/` and installs locked runtime + dev dependencies from [`uv.lock`](uv.lock).

3. **Run the tool** (no global `PATH` change required):

   ```bash
   uv run secanalyzer --help
   ```

   Optional: activate the venv and call the console script directly:

   ```bash
   source .venv/bin/activate   # Linux / WSL
   secanalyzer --help
   ```

---

## CI/CD

Continuous integration runs on **every push** and **pull request** to `main` or `master` (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

### What the pipeline does

| Step | Tool | Purpose |
|---|---|---|
| **Locked install** | `uv sync --frozen --all-groups` | Reproducible environment from [`uv.lock`](uv.lock) (runtime + dev) |
| **Unit tests** | `pytest` | Full test suite |
| **Static security analysis** | `bandit` | Python source patterns (`src/secanalyzer`) |
| **Dependency audit** | `pip-audit` | Known CVEs in the resolved environment |

### Viewing build status

Open the **Actions** tab on GitHub for this repository. A green workflow run means all steps passed.

### Running the same checks locally

```bash
uv sync --frozen --all-groups
uv run pytest
uv run bandit -r src/secanalyzer
uv run pip-audit
```

---

## Token Setup

Credentials are stored in local files and are **never** hard-coded or committed to the repository.

1. **GitHub Token**

   Create a Personal Access Token at [github.com/settings/tokens](https://github.com/settings/tokens) with the `repo` scope, then store it:

   ```bash
   uv run secanalyzer --set-token github
   # You will be prompted to paste your token securely
   ```

2. **LLM API Key**

   ```bash
   uv run secanalyzer --set-token llm --provider claude
   # Or: --provider gemini — prompts for API key (hidden)
   ```

3. **Verify all keys are valid:**

   ```bash
   uv run secanalyzer --api-key-status
   ```

   Expected output:

   ```
   [OK]  GitHub token — valid
   [OK]  LLM API key  — valid (provider: claude)
   ```

---

## Quickstart

**First-time setup from zero:** follow **[QUICKSTART.md](QUICKSTART.md)** (install uv, `uv sync`, tokens, verify, then run the commands below).

**Generate documentation for a repository:**

```bash
uv run secanalyzer --scan /path/to/your/repo
```

Optional: write the Markdown report to a file:

```bash
uv run secanalyzer --scan /path/to/your/repo -o report.md
```

**Fetch and analyze open issues and PRs:**

```bash
uv run secanalyzer --issues owner/repo-name
```

You will be presented with an interactive menu (navigable with arrow keys and Enter). Select an item to receive its risk classification and a suggested fix.

---

## CLI Reference

| Flag | Argument | Description |
|---|---|---|
| `--scan` | `<path>` | Recursively scan a local repository and generate security documentation (Markdown). |
| `-o` / `--output` | `<file>` | With `--scan`, write Markdown to a file instead of stdout. |
| `--issues` | `<owner/repo>` | Fetch open issues and PRs from GitHub and launch the interactive analyzer. |
| `--api-key-status` | — | Check whether configured API keys are present and valid. |
| `--set-token` | `github \| llm` | Securely store a new credential (use `--provider` with `llm`). |
| `--provider` | `claude \| gemini \| anthropic` | With `--set-token llm`, choose vendor. With `--issues`, must match the stored vendor. |
| `--help` | — | Display usage information. |

All interactive menus are fully keyboard-navigable (↑ ↓ arrow keys, Enter to select, Escape to go back).

---

## Security and Data Handling

This tool is built with a security-first design. Key guarantees:

- **Credentials are never exposed.** GitHub tokens and LLM API keys are stored in local files, loaded into memory only at the moment of an API call, and are never included in log output, error messages, or LLM prompts. A pre-send filter scans every prompt for credential-shaped patterns and aborts the request if any are detected.

- **Secrets in your code are redacted.** Before any file content is sent to an LLM, the tool runs a secrets-detection pass and strips or masks detected credentials, private keys, and PII patterns. You will see a warning in the terminal whenever content is redacted.

- **Path traversal is prevented.** The repository path is resolved to an absolute canonical path, and all scanned files are verified to remain within that root. Only allowlisted file extensions are read (`.py`, `.js`, `.ts`, `.go`, `.c`, `.cpp`, and others).

- **Prompt injection is mitigated.** All user-controlled text (PR titles, bodies, diffs) is wrapped in a clearly delimited data section of the system prompt, separate from instructions. LLM responses are validated against an expected schema before being acted upon.

- **Dependencies are locked.** Third-party packages are pinned in [`uv.lock`](uv.lock). CI runs `uv sync --frozen --all-groups` and **`pip-audit`** on every push/PR. Review lockfile changes in PRs like any other security-sensitive diff.

For full details on data handling guarantees and how to report a vulnerability, see [SECURITY.md](SECURITY.md).

---

## Troubleshooting

**`command not found: secanalyzer`**

Use `uv run secanalyzer …` from the project directory, or activate the venv first: `source .venv/bin/activate` (Linux/WSL) then `secanalyzer`. You can also run `uv run python -m secanalyzer`.

**`[ERROR] GitHub token is missing or invalid`**

Run `uv run secanalyzer --set-token github` to re-enter your token, then verify with `uv run secanalyzer --api-key-status`.

**`[ERROR] LLM API key is missing or invalid`**

Run `uv run secanalyzer --set-token llm --provider claude` (or `gemini`). Use `--api-key-status` to confirm.

**`[WARNING] API unavailable — cannot reach GitHub`**

Check your internet connection. If the issue persists, GitHub may be experiencing an outage.

**`[WARNING] Content redacted before sending to LLM`** / **`Aborting LLM request: credential-shaped patterns`**

The pre-send filter or scan redactor detected patterns that look like secrets. Remove real credentials from the issue/PR or scanned tree, or reduce included PR diff size, then retry.

**Slow or truncated context on large repositories / PRs**

The tool targets an estimated **100,000 LLM tokens per request** (M2). Use `--scan` on a subdirectory if needed; PR patch text is already truncated server-side.

**`uv sync --frozen` fails after pulling**

The lockfile may be out of date relative to `pyproject.toml`. A maintainer should run `uv lock` and commit the updated `uv.lock`. Do not hand-edit locked versions without verifying sources.

---

## Contributing

This project follows a weekly sprint cadence. The active backlog is maintained on the [GitHub Project Board](https://github.com/users/flufcloud/projects/2/views/1).

To report a security vulnerability, please follow the responsible disclosure process documented in [SECURITY.md](SECURITY.md) rather than opening a public issue.
