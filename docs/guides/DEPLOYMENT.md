# Deployment Guide

`secanalyzer` deploys as a local Python CLI. There is no server, daemon, database, or cloud runtime to provision.

## Target environment

- Linux or WSL2
- Python 3.11+
- `uv` 0.5+
- Git
- Optional: GitHub PAT for `--list-issues` / `--analyze-issue`
- Optional: Anthropic or Google AI key for LLM-backed commands

## Build from source

```bash
git clone https://github.com/flufcloud/366_project.git
cd 366_project
uv sync --frozen --all-groups
uv build
```

Artifacts are written to `dist/`. For normal local use, `uv run secanalyzer ...` from the repo root is sufficient.

## Install and verify

```bash
uv sync --frozen --all-groups
uv run pytest
uv run bandit -r src/secanalyzer
uv run pip-audit
uv run secanalyzer --help
```

For a runtime-only installation from a built wheel:

```bash
uv venv
uv pip install dist/secanalyzer-*.whl
uv run secanalyzer --help
```

## Configure credentials

Credentials are stored under the OS user config directory, not in the repository.

```bash
uv run secanalyzer --set-token github
uv run secanalyzer --set-token llm --provider claude
uv run secanalyzer --api-key-status
```

Use `--provider gemini` for Google AI Studio keys. Use `--list-google-models` and `--set-google-model MODEL` if the default Google model is unavailable for your account.

## Run production commands

Static scan, no LLM:

```bash
uv run secanalyzer --scan /path/to/repo -o static-report.md
```

LLM-backed repository report:

```bash
uv run secanalyzer --llm-report /path/to/repo -o llm-report.md
```

GitHub issue/PR list:

```bash
uv run secanalyzer --list-issues owner/repo
```

One issue/PR analysis:

```bash
uv run secanalyzer --analyze-issue owner/repo --issue-number 42 -o issue-42.md
```

## Operations

Operational logs are local JSONL files. They record command lifecycle, scan counts, redaction hits, Bandit counts, GitHub/LLM failures, and retry pressure. Token-like fields are redacted before write.

```bash
SECANALYZER_LOG_FILE=./operations.jsonl uv run secanalyzer --scan .
SECANALYZER_LOG_DISABLE=1 uv run secanalyzer --help
```

Review logs before sharing them because they can include repository paths, issue titles, and other contextual data.

## Release checklist

- `uv sync --frozen --all-groups`
- `uv run pytest`
- `uv run bandit -r src/secanalyzer`
- `uv run pip-audit`
- `uv run secanalyzer --help`
- Update [ISSUE_LOG.md](../reports/ISSUE_LOG.md) for accepted risks and technical debt.
- Review changes to `pyproject.toml` and `uv.lock` as security-sensitive.
