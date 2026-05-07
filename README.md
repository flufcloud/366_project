# AI-Powered Codebase Security Analyzer

A local Linux command-line tool that uses large language models to help developers and security engineers understand, document, and evaluate the security posture of a codebase.

Point the tool at any repository and it will automatically generate structured documentation of the codebase's architecture and data flow, fetch open GitHub issues and pull requests, classify each item by security risk level (low / medium / high), and propose preliminary root causes and suggested fixes — all without ever leaving your machine beyond the API calls you explicitly authorize.

---

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Building from Source](#building-from-source)
- [Installation](#installation)
- [CI/CD](#cicd)
- [Token Setup](#token-setup)
- [Quickstart](#quickstart)
- [CLI Reference](#cli-reference)
- [Security and Data Handling](#security-and-data-handling)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

---

## Features

| Feature | Description |
|---|---|
| **Codebase Documentation Engine** | Recursively scans a repository and produces Markdown documentation covering architecture, data flow, and security considerations. |
| **Issue & PR Analyzer** | Authenticates with GitHub, presents an interactive menu of open issues and PRs, and classifies each item's security risk with a justification. |
| **Preliminary Solutions** | For every flagged issue or PR, generates a plain-language suggested fix or direction of investigation. |
| **Multi-LLM Support** | Choose your own LLM backend — Claude, Gemini, and others are supported. |
| **Security-First Design** | Secrets are redacted before any data is sent to an LLM. Credentials are never logged or printed to stdout. |

---

## Prerequisites

- **OS:** Linux (Ubuntu 20.04+ or Debian 11+ recommended)
- **Python:** 3.11 or higher
- **pip:** 23.0 or higher
- **Git:** Any recent version
- A **GitHub Personal Access Token** with `repo` scope
- An API key for your chosen LLM provider (Claude, Gemini, etc.)

Verify your Python version before installing:

```bash
python3 --version
```

---

## Building from Source

The project uses `pyproject.toml` with `setuptools` as its build backend. This lets you build a proper installable Python package (a `.whl` wheel file) from source, which is what `install.sh` does under the hood. You can also do it manually.

1. **Install the build frontend** (one-time):

```bash
pip install build --break-system-packages
```

2. **Build the wheel and source distribution:**

```bash
python3 -m build
```

This produces two artifacts inside the `dist/` directory:

```
dist/
  secanalyzer-0.1.0-py3-none-any.whl   # installable wheel
  secanalyzer-0.1.0.tar.gz              # source distribution
```

3. **Install the built wheel into a virtual environment:**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --require-hashes -r requirements.txt
pip install dist/secanalyzer-0.1.0-py3-none-any.whl
```

4. **Run tests to verify the build is clean:**

```bash
pytest tests/
```

> **Note:** The `install.sh` convenience script wraps all of these steps. Use it for a standard first-time setup. Build manually only if you are modifying the package or verifying build reproducibility.

---

## Installation

> **Warning:** Always verify dependency hashes before installation (see [Security and Data Handling](#security-and-data-handling)).

1. **Clone the repository:**

```bash
git clone https://github.com/flufcloud/366_project.git
cd 366_project
```

2. **Run the install script:**

```bash
chmod +x install.sh
./install.sh
```

The install script will create a virtual environment, install all pinned dependencies with hash verification, and place the `secanalyzer` command on your `PATH`.

3. **Verify the installation:**

```bash
secanalyzer --help
```

---

## CI/CD

This project uses **GitHub Actions** for continuous integration. The pipeline is defined in `.github/workflows/ci.yml` and is triggered automatically on every push to `main` and on every pull request targeting `main`.

### What the pipeline does

| Step | Tool | Purpose |
|---|---|---|
| **Install dependencies** | `pip` + `--require-hashes` | Installs pinned, hash-verified dependencies |
| **Static security analysis** | `bandit` | Scans source code for common Python security issues |
| **Dependency vulnerability check** | `pip-audit` | Flags dependencies with known CVEs |
| **Unit tests** | `pytest` | Runs the full test suite |

### Viewing build status

You can check the status of any run in the [Actions tab](https://github.com/flufcloud/366_project/actions) of the repository. A green checkmark on a PR means all four steps passed. Merging is blocked if any step fails.

### Running the pipeline locally

You can replicate the CI steps locally before pushing:

```bash
# Static analysis
bandit -r secanalyzer/

# Dependency audit
pip-audit

# Tests
pytest tests/
```

---

## Token Setup

Credentials are stored in local files and are **never** hard-coded or committed to the repository.

1. **GitHub Token**

   Create a Personal Access Token at [github.com/settings/tokens](https://github.com/settings/tokens) with the `repo` scope, then store it:

   ```bash
   secanalyzer --set-token github
   # You will be prompted to paste your token securely
   ```

2. **LLM API Key**

   ```bash
   secanalyzer --set-token llm
   # You will be prompted to select your provider and paste your key
   ```

3. **Verify all keys are valid:**

   ```bash
   secanalyzer --api-key-status
   ```

   Expected output:

   ```
   [OK]  GitHub token — valid
   [OK]  LLM API key  — valid (provider: claude)
   ```

---

## Quickstart

**Generate documentation for a repository:**

```bash
secanalyzer --scan /path/to/your/repo
```

**Fetch and analyze open issues and PRs:**

```bash
secanalyzer --issues owner/repo-name
```

You will be presented with an interactive menu (navigable with arrow keys and Enter). Select an item to receive its risk classification and a suggested fix.

---

## CLI Reference

| Flag | Argument | Description |
|---|---|---|
| `--scan` | `<path>` | Recursively scan a local repository and generate security documentation. |
| `--issues` | `<owner/repo>` | Fetch open issues and PRs from GitHub and launch the interactive analyzer. |
| `--api-key-status` | — | Check whether all configured API keys are present and valid. |
| `--set-token` | `github \| llm` | Securely store a new credential. |
| `--provider` | `claude \| gemini \| ...` | Override the default LLM provider for this invocation. |
| `--help` | — | Display usage information. |

All interactive menus are fully keyboard-navigable (↑ ↓ arrow keys, Enter to select, Escape to go back).

---

## Security and Data Handling

This tool is built with a security-first design. Key guarantees:

- **Credentials are never exposed.** GitHub tokens and LLM API keys are stored in local files, loaded into memory only at the moment of an API call, and are never included in log output, error messages, or LLM prompts. A pre-send filter scans every prompt for credential-shaped patterns and aborts the request if any are detected.

- **Secrets in your code are redacted.** Before any file content is sent to an LLM, the tool runs a secrets-detection pass and strips or masks detected credentials, private keys, and PII patterns. You will see a warning in the terminal whenever content is redacted.

- **Path traversal is prevented.** The repository path is resolved to an absolute canonical path, and all scanned files are verified to remain within that root. Only allowlisted file extensions are read (`.py`, `.js`, `.ts`, `.go`, `.c`, `.cpp`, and others).

- **Prompt injection is mitigated.** All user-controlled text (PR titles, bodies, diffs) is wrapped in a clearly delimited data section of the system prompt, separate from instructions. LLM responses are validated against an expected schema before being acted upon.

- **Dependencies are pinned and hash-verified.** `requirements.txt` pins every dependency to an exact version with a cryptographic hash. The install script uses `pip install --require-hashes` and the CI pipeline runs `pip-audit` on every push.

For full details on data handling guarantees and how to report a vulnerability, see [SECURITY.md](SECURITY.md).

---

## Troubleshooting

**`command not found: secanalyzer`**
The install script may not have updated your `PATH`. Run `source ~/.bashrc` (or `~/.zshrc`) and try again, or invoke the tool directly with `python3 -m secanalyzer`.

**`[ERROR] GitHub token is missing or invalid`**
Run `secanalyzer --set-token github` to re-enter your token, then verify with `secanalyzer --api-key-status`.

**`[ERROR] LLM API key is missing or invalid`**
Run `secanalyzer --set-token llm`. Make sure you selected the correct provider with `--provider`.

**`[WARNING] API unavailable — cannot reach GitHub`**
Check your internet connection. If the issue persists, GitHub may be experiencing an outage. The tool will not proceed when the API is unreachable.

**`[WARNING] Content redacted before sending to LLM`**
The pre-send filter detected a potential secret in a file. Review the flagged file and ensure it does not contain real credentials before re-running.

**Slow documentation generation on large repositories**
The tool enforces a budget of 100,000 LLM tokens per request. For very large codebases, consider scanning a subdirectory with `--scan /path/to/repo/src` instead of the entire repo root.

**Dependency hash mismatch during install**
Do not proceed. This may indicate a supply chain attack or a corrupted download. Re-clone the repository, verify the `requirements.txt` hashes against the values in this README's release notes, and open an issue if the mismatch persists.

---

## Contributing

This project follows a weekly sprint cadence. The active backlog is maintained on the [GitHub Project Board](https://github.com/users/flufcloud/projects/2/views/1).

To report a security vulnerability, please follow the responsible disclosure process documented in [SECURITY.md](SECURITY.md) rather than opening a public issue.
