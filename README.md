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
- [Quickstart guide (step-by-step)](docs/guides/QUICKSTART.md)
- [Deployment guide](docs/guides/DEPLOYMENT.md)
- [CLI Reference](#cli-reference)
- [Security and Data Handling](#security-and-data-handling)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Architecture & security reports](docs/reports/TECHNICAL_REPORT.md) — see also [security report](docs/reports/SECURITY_REPORT.md)

---

## Features

| Feature | Description |
|---|---|
| **Codebase Documentation Engine** | Scans allowlisted files, emits a compact Markdown **inventory**, and (when an LLM key is stored) appends a **concise narrative** from a bounded excerpt of the tree — not a full code dump. |
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
- A **GitHub Personal Access Token** with `repo` scope (for `--list-issues` / `--analyze-issue`)
- An API key for your chosen LLM provider (**Claude** / **Gemini**) for `--analyze-issue`

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

Detailed documentation is organized under `docs/`:

| Folder | Contents |
|---|---|
| [`docs/guides/`](docs/guides/) | User guides, quickstart, security policy, deployment notes. |
| [`docs/reports/`](docs/reports/) | Course milestone reports, technical report, security report, presentation brief, issue log. |

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

**First-time setup from zero:** follow **[QUICKSTART.md](docs/guides/QUICKSTART.md)** (install uv, `uv sync`, tokens, verify, then run the commands below).

**Static scan (inventory only, no LLM):**

```bash
uv run secanalyzer --scan /path/to/your/repo
uv run secanalyzer --scan /path/to/your/repo -o static-report.md
```

**LLM security report (per-file analysis, unified narrative):**

```bash
uv run secanalyzer --llm-report /path/to/your/repo -o llm-report.md
```

Requires `secanalyzer --set-token llm`. Progress is printed to stderr.

**List open issues and PRs (non-interactive):**

```bash
uv run secanalyzer --list-issues owner/repo-name
```

**Analyze one issue or PR (brief security overview):**

```bash
uv run secanalyzer --analyze-issue owner/repo-name --issue-number 42
uv run secanalyzer --analyze-issue owner/repo-name --issue-number 42 -o issue-42.md
```

By default the model sees the issue title, body, and comment thread (plus a truncated PR diff when applicable). To augment with codebase context from a prior `--llm-report` artifact tree:

```bash
uv run secanalyzer --analyze-issue owner/repo --issue-number 42 \
  --report-context ./my-repo-llm-report \
  --report-scope apps/api
```

`--report-scope` selects the nearest `compaction/by-directory/<scope>/*-rolling-summary.md` (walking up parents). If omitted, the tool uses `compaction/final-rolling-summary.md` or infers a scope from PR file paths.

---

## CLI Reference

| Flag | Argument | Description |
|---|---|---|
| `--scan` | `<path>` | Static repository scan (Markdown inventory only; no LLM). |
| `--llm-report` | `<path>` | LLM security report: one file per request, compact context, synthesize Markdown. |
| `-o` / `--output` | `<file>` | With `--scan`, `--llm-report`, or `--analyze-issue`, write Markdown to a file. |
| `--list-issues` | `<owner/repo>` | List open issues and PRs (Markdown table to stdout). |
| `--analyze-issue` | `<owner/repo>` | LLM brief security overview for one item (requires `--issue-number`). |
| `--issue-number` | `N` | Issue or PR number (with `--analyze-issue`). |
| `--report-context` | `<dir>` | `--llm-report` artifact tree for rolling codebase context. |
| `--report-scope` | `<path>` | Repo-relative directory for directory-level rolling summary (with `--report-context`). |
| `--api-key-status` | — | Check whether configured API keys are present and valid. |
| `--set-token` | `github \| llm` | Securely store a new credential (use `--provider` with `llm`). |
| `--provider` | `claude \| gemini \| anthropic` | With `--set-token llm` or `--analyze-issue`, choose or match vendor. |
| `--help` | — | Display usage information. |

---

## Security and Data Handling

This tool is built with a security-first design. Key guarantees:

- **Credentials are never exposed.** GitHub tokens and LLM API keys are stored in local files, loaded into memory only at the moment of an API call, and are never included in log output, error messages, or LLM prompts. A pre-send filter scans every prompt for credential-shaped patterns and aborts the request if any are detected.

- **Secrets in your code are redacted.** Before any file content is sent to an LLM, the tool runs a secrets-detection pass and strips or masks detected credentials, private keys, and PII patterns. You will see a warning in the terminal whenever content is redacted.

- **Path traversal is prevented.** The repository path is resolved to an absolute canonical path, and all scanned files are verified to remain within that root. Only allowlisted file extensions are read (`.py`, `.js`, `.ts`, `.go`, `.c`, `.cpp`, and others).

- **Prompt injection is mitigated.** All user-controlled text (PR titles, bodies, diffs) is wrapped in a clearly delimited data section of the system prompt, separate from instructions. LLM responses are validated against an expected schema before being acted upon.

- **Dependencies are locked.** Third-party packages are pinned in [`uv.lock`](uv.lock). CI runs `uv sync --frozen --all-groups` and **`pip-audit`** on every push/PR. Review lockfile changes in PRs like any other security-sensitive diff.

For full details on data handling guarantees and how to report a vulnerability, see [SECURITY.md](docs/guides/SECURITY.md).

### Operational logging

Every CLI run writes sanitized JSONL operational events to the user log directory by default:

```bash
uv run python - <<'PY'
from pathlib import Path
from platformdirs import user_log_dir
print(Path(user_log_dir("secanalyzer", appauthor=False)) / "operations.jsonl")
PY
```

The log records command lifecycle events, scan counts, redaction hits, Bandit results, GitHub/LLM API failures, and retry pressure. Token-like fields are redacted before write. Set `SECANALYZER_LOG_FILE=/path/to/operations.jsonl` to choose a location, `SECANALYZER_LOG_LEVEL=DEBUG|INFO|WARNING|ERROR` for verbosity, or `SECANALYZER_LOG_DISABLE=1` to disable file logging.

---

## Troubleshooting

**`Project virtual environment directory ... cannot be used ... (no Python executable was found)`** (often in **WSL**)

The `.venv` in this repo was almost certainly created on **Windows** (`Scripts\python.exe`). Linux/WSL expects `bin/python`. From the project root in WSL, remove the old env and sync again:

```bash
rm -rf .venv
uv sync --all-groups
```

Prefer keeping the project under the **Linux filesystem** (e.g. `~/366_project`) if you mainly use WSL, to avoid cross-OS venv confusion on `/mnt/c/...`.

**`command not found: secanalyzer`**

Use `uv run secanalyzer …` from the project directory, or activate the venv first: `source .venv/bin/activate` (Linux/WSL) then `secanalyzer`. You can also run `uv run python -m secanalyzer`.

**`[ERROR] GitHub token is missing or invalid`**

Run `uv run secanalyzer --set-token github` to re-enter your token, then verify with `uv run secanalyzer --api-key-status`.

**`[ERROR] LLM API key is missing or invalid`**

Run `uv run secanalyzer --set-token llm --provider claude` (or `gemini`). Use `--api-key-status` to confirm.

**`[WARNING] API unavailable — cannot reach GitHub`**

Check your internet connection. If the issue persists, GitHub may be experiencing an outage.

**LLM rate limits or strict per-request token caps**

The default Google model is **Gemma 3** (`gemma-3-12b-it`) on the same AI Studio API key as Gemini. Override with `SECANALYZER_GEMMA_MODEL` (e.g. `gemma-3-4b-it`, `gemma-3-27b-it`) or `SECANALYZER_GEMINI_MODEL` for Gemini. Gemma still has RPM/RPD limits on free tiers (often more generous than Gemini Flash daily caps).

Set `SECANALYZER_LLM_MAX_USER_TOKENS` for smaller per-request payloads. For large `--llm-report` runs, use `SECANALYZER_LLM_BATCH_DELAY_SEC` (default `0.65`) and optionally `SECANALYZER_LLM_MAX_FILES`.

**`[WARNING] Content redacted before sending to LLM`** / **`Aborting LLM request: credential-shaped patterns`**

The pre-send filter or scan redactor detected patterns that look like secrets. Remove real credentials from the issue/PR or scanned tree, or reduce included PR diff size, then retry.

**Slow or truncated context on large repositories / PRs**

The tool targets an estimated **100,000 LLM tokens per request** (M2). Use `--scan` on a subdirectory if needed; PR patch text is already truncated server-side.

**`uv sync --frozen` fails after pulling**

The lockfile may be out of date relative to `pyproject.toml`. A maintainer should run `uv lock` and commit the updated `uv.lock`. Do not hand-edit locked versions without verifying sources.

---

## Contributing

This project follows a weekly sprint cadence. The active backlog is maintained on the [GitHub Project Board](https://github.com/users/flufcloud/projects/2/views/1).

To report a security vulnerability, please follow the responsible disclosure process documented in [SECURITY.md](docs/guides/SECURITY.md) rather than opening a public issue.
