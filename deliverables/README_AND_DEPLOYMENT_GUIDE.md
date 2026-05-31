# README and Deployment Guide

Project: **AI-Powered Codebase Security Analyzer (`secanalyzer`)**  
Repository: [https://github.com/flufcloud/366_project](https://github.com/flufcloud/366_project)

## What this system does

`secanalyzer` is a local Python command-line tool for security-oriented codebase review. A user points it at a repository, and it can:

- produce a deterministic Markdown inventory of allowlisted source/config files;
- run Bandit static analysis on production Python source;
- generate an LLM-assisted security report with bounded per-file analysis;
- list GitHub issues and pull requests;
- generate a brief security overview for a selected GitHub issue or PR.

The tool is designed for a developer or security engineer who wants a fast first-pass view of a codebase, its trust boundaries, and GitHub work items that may deserve security attention.

## Repository layout

| Path | Purpose |
|------|---------|
| `src/secanalyzer/` | Production application code |
| `tests/` | pytest suite |
| `README.md` | Main project README |
| `docs/guides/QUICKSTART.md` | Step-by-step first run |
| `docs/guides/DEPLOYMENT.md` | Full deployment/runbook instructions |
| `docs/guides/SECURITY.md` | Security policy and data handling |
| `docs/reports/` | Milestone reports, threat model, final report, security report |
| `deliverables/` | Final submission package |
| `issues/` | Local issue-ticket files for risks not yet writable to GitHub Issues |

## Requirements

- Linux or WSL2
- Python 3.11+
- `uv` 0.5+
- Git
- Optional: GitHub personal access token for `--list-issues` and `--analyze-issue`
- Optional: Anthropic Claude or Google AI Studio key for LLM-backed commands

## Build and install

From the repository root:

```bash
uv sync --frozen --all-groups
uv build
```

For normal use during development or demonstration:

```bash
uv run secanalyzer --help
```

For a wheel-based install in a local virtual environment:

```bash
uv venv
uv pip install dist/secanalyzer-*.whl
uv run secanalyzer --help
```

## Configure credentials

Credentials are stored in the OS user config directory, not in the repository.

```bash
uv run secanalyzer --set-token github
uv run secanalyzer --set-token llm --provider claude
uv run secanalyzer --api-key-status
```

Use `--provider gemini` for Google AI Studio keys. If Google model access fails, run:

```bash
uv run secanalyzer --list-google-models
uv run secanalyzer --set-google-model MODEL
```

## Run the application

Static scan, no LLM:

```bash
uv run secanalyzer --scan /path/to/repo -o static-report.md
```

LLM-backed repository security report:

```bash
uv run secanalyzer --llm-report /path/to/repo -o llm-report.md
```

List GitHub work items:

```bash
uv run secanalyzer --list-issues owner/repo
```

Analyze one issue or PR:

```bash
uv run secanalyzer --analyze-issue owner/repo --issue-number 42 -o issue-42.md
```

Use a prior LLM report as codebase context:

```bash
uv run secanalyzer --analyze-issue owner/repo --issue-number 42 \
  --report-context ./my-report.report-tree \
  --report-scope src/secanalyzer
```

## Monitoring and logging

The final release includes local operational logging in `src/secanalyzer/operations.py`. Logs are written as JSONL events to the OS user log directory by default and include:

- command start/completion/failure;
- scan file counts and redaction hits;
- Bandit result counts;
- GitHub API failures;
- LLM request starts/completions, retry pressure, and pre-send security blocks.

Token-like fields are redacted before they are written.

To choose a log location:

```bash
SECANALYZER_LOG_FILE=./operations.jsonl uv run secanalyzer --scan .
```

To disable local file logging:

```bash
SECANALYZER_LOG_DISABLE=1 uv run secanalyzer --help
```

Review operational logs before sharing them. They should not contain credentials, but they may contain repository paths, issue numbers, and other contextual information.

## Security posture

Primary controls:

- path confinement with resolved scan roots;
- extension allowlist;
- binary and non-UTF-8 file skips;
- secret redaction before reports and LLM prompts;
- LLM pre-send abort when credential-shaped patterns remain;
- delimiter-wrapped untrusted GitHub and repository content;
- schema validation for structured LLM responses;
- user-facing errors instead of raw tracebacks;
- locked dependencies with `uv.lock`;
- CI gates for pytest, Bandit, and `pip-audit`.

Detailed security analysis is in `docs/reports/SECURITY_REPORT.md`. Security policy and data handling rules are in `docs/guides/SECURITY.md`.

## Validation commands

Run before release or presentation:

```bash
uv sync --frozen --all-groups
uv run pytest
uv run bandit -r src/secanalyzer
uv run pip-audit
uv run secanalyzer --help
uv run secanalyzer --scan . -o tmp-static-report.md
```

Latest validation result from the final hardening pass:

| Gate | Result |
|------|--------|
| pytest | 99 passed, 1 skipped |
| Bandit | No issues identified |
| pip-audit | No known vulnerabilities found; local package skipped because it is not on PyPI |
| CLI help | Printed successfully |
| Static scan smoke test | Completed; embedded Bandit reported 0 production-source issues |

## Related documentation

- `deliverables/FINAL_WRITTEN_REPORT.md`
- `deliverables/RETROSPECTIVE.md`
- `deliverables/ISSUE_LOG.md`
- `docs/reports/M2_Agile_Requirements.md`
- `docs/reports/M3_Design_Document_ThreatModeling.md`
- `docs/reports/M4_Beta_Release_Report.md`
- `docs/reports/M5_Final_Release_Report.md`
