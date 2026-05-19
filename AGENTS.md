# AGENTS.md — secanalyzer

Living notes for humans and coding agents. **Update this file** as phases complete (checklists, commands, decisions).

## Project map

| Path | Role |
|------|------|
| [pyproject.toml](pyproject.toml) | Package metadata, console script `secanalyzer`, pytest + **bandit** config |
| [.github/workflows/ci.yml](.github/workflows/ci.yml) | CI: `uv sync --frozen`, pytest, bandit, pip-audit |
| [src/secanalyzer/](src/secanalyzer/) | Application code |
| [src/secanalyzer/exceptions.py](src/secanalyzer/exceptions.py) | `UserFacingError`, `GitHubApiError`, `LLMError`, etc. (CLI → stderr, no tracebacks) |
| [tests/](tests/) | `pytest` suite |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting + data-handling guarantees |
| [QUICKSTART.md](QUICKSTART.md) | Step-by-step: install, tokens, `--scan`, `--list-issues`, `--analyze-issue` |
| [docs/TECHNICAL_REPORT.md](docs/TECHNICAL_REPORT.md) | Architecture, data flows, engineering decisions (presentation-oriented) |
| [docs/SECURITY_REPORT.md](docs/SECURITY_REPORT.md) | Threat catalog ↔ mitigations ↔ code/CI mapping |
| [M2_Agile_Requirements.md](M2_Agile_Requirements.md) | MVP, NFRs, acceptance criteria |
| [M3_Design_Document_ThreatModeling.md](M3_Design_Document_ThreatModeling.md) | Components A1–A6, threats, mitigations (file contains large base64 after §5 — use lines 1–98 for text) |

## Architecture (M3 §2.1)

| Component | Module |
|-----------|--------|
| CLI Interface | [src/secanalyzer/cli.py](src/secanalyzer/cli.py) |
| ConfigManager | [src/secanalyzer/config.py](src/secanalyzer/config.py) |
| RepositoryAnalyzer | [src/secanalyzer/repo_analyzer.py](src/secanalyzer/repo_analyzer.py) |
| GitHub API Client | [src/secanalyzer/github_client.py](src/secanalyzer/github_client.py) |
| LLM Orchestration Layer | [src/secanalyzer/llm.py](src/secanalyzer/llm.py) |
| Issues / PR TUI glue | [src/secanalyzer/issues_session.py](src/secanalyzer/issues_session.py) |
| OutputHandler | [src/secanalyzer/output.py](src/secanalyzer/output.py) |

## UV + WSL (local dev)

All dependencies stay inside this repo (`.venv/` created by UV).

```bash
# From repo root (in WSL, e.g. cd /mnt/c/Users/.../366_project)
uv sync --all-groups
uv run pytest
uv run bandit -r src/secanalyzer
uv run pip-audit
uv run secanalyzer --help
```

Windows PowerShell uses the same commands; for course deliverables, prefer validating in **WSL Ubuntu** to match the Linux target.

### Test-only config override

If `SECANALYZER_CONFIG_DIR` is set to a directory path, credentials are read/written **only** there (used by pytest). Do not point it at a shared folder in production.

### Optional model overrides (Phase 3)

| Environment variable | Default | Purpose |
|------------------------|---------|---------|
| `SECANALYZER_ANTHROPIC_MODEL` | `claude-3-5-haiku-20241022` | Anthropic Messages API model id |
| `SECANALYZER_GEMMA_MODEL` / `SECANALYZER_GEMINI_MODEL` | `gemma-3-27b-it` | Google AI `generateContent` model id (Gemma 3 IT or Gemini; same API key). Run `secanalyzer --list-google-models` if you get HTTP 404. Examples: `gemma-3-27b-it`, `gemini-2.5-flash`. |
| `SECANALYZER_LLM_COMPACT_EVERY` | `8` | After N per-file analyses, compact rolling context (`--llm-report`) |
| `SECANALYZER_LLM_FILE_MAX_USER_TOKENS` | (same as global budget) | Per-file user-message cap for `--llm-report` |
| `SECANALYZER_LLM_MAX_FILES` | (unset) | Optional cap on files analyzed in one `--llm-report` run |
| `SECANALYZER_LLM_ROLLING_MAX_TOKENS` | `2500` | Max estimated tokens kept in rolling summary between compactions |
| `SECANALYZER_LLM_COMPACT_BATCH_MAX_TOKENS` | `3500` | Max tokens for one compaction batch JSON (typically ≤8 files) |
| `SECANALYZER_LLM_COMPACT_MAX_USER_TOKENS` | `8000` | User-message cap for compaction + final synthesis calls |

## Phase checklist

### Phase 1 — Skeleton

- [x] `pyproject.toml` + `uv.lock`, Python ≥3.11, `src/secanalyzer` layout
- [x] Console entrypoint `secanalyzer` → `secanalyzer.cli:main`
- [x] Six component modules present
- [x] CLI: `--help`, `--version`, declared flags
- [x] `pytest` + `python -m secanalyzer` smoke test
- [x] `AGENTS.md` created

### Phase 2 — Secure local core

- [x] ConfigManager + `--scan` + redaction + `SECURITY.md` draft

### Phase 3 — GitHub + LLM

- [x] `--list-issues`, `--analyze-issue`, Anthropic/Gemini, optional `--llm-report` tree context

### Phase 4 — CI + docs (current)

- [x] [`.github/workflows/ci.yml`](.github/workflows/ci.yml): `astral-sh/setup-uv@v5`, `uv sync --frozen --all-groups`, `pytest`, `bandit -r src/secanalyzer`, `pip-audit` (push/PR to `main` or `master`)
- [x] Dev deps: `bandit`, `pip-audit`; `[tool.bandit]` in `pyproject.toml`
- [x] [README.md](README.md): UV-first install, CI table, troubleshooting, accurate `--scan` / lockfile wording
- [x] [SECURITY.md](SECURITY.md): CI + supply chain section finalized
- [x] Tests: **45** passed, **1** skipped (Windows symlink)

## Changelog

| Date | Note |
|------|------|
| 2026-05-13 | Phase 1 complete: UV package, CLI scaffold, **12** tests green, `python -m secanalyzer` via `__main__.py`. |
| 2026-05-13 | Phase 2 complete: config + `--scan` + redaction + `SECURITY.md`; **30** tests passed (**1** symlink skipped on Windows). |
| 2026-05-13 | Phase 3 complete: `--issues`, questionary UI, Anthropic/Gemini orchestration, M2/M3 controls; **45** passed (**1** skipped). |
| 2026-05-13 | Phase 4 complete: GitHub Actions CI, bandit + pip-audit in dev group, README/SECURITY aligned with **uv** + lockfile. |
