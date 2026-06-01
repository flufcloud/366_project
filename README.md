# secanalyzer

Local CLI for LLM-powered codebase security reviewer.

## Deliverables

- [Final Written Report PDF](deliverables/final_report.docx.pdf)
- [Retrospective PDF](deliverables/retrospective.pdf)
- [Presentation Slides PDF](deliverables/slides.pdf)
- Issue Tracker through Github Issues.
- Detailed documentation on deployment [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)

Previous milestone docs:

- [M2 Agile Requirements](milestones/M2_Agile_Requirements.md)
- [M3 Design and Threat Modeling](milestones/M3_Design_Document_ThreatModeling.md)
- [M4 Beta Release Report](milestones/M4_Beta_Release_Report.md)
- [M5 Final Release Report](milestones/M5_Final_Release_Report.md)

## Quickstart

```bash
git clone https://github.com/flufcloud/366_project.git
cd 366_project
uv sync --frozen --all-groups
uv run secanalyzer --help
```

Run a local static scan:

```bash
uv run secanalyzer --scan /path/to/repo -o static-report.md
```

Run an LLM-backed codebase report:

```bash
uv run secanalyzer --llm-report /path/to/repo -o llm-report.md
```

List GitHub issues/PRs:

```bash
uv run secanalyzer --list-issues owner/repo
```

Analyze one GitHub issue or PR:

```bash
uv run secanalyzer --analyze-issue owner/repo --issue-number 42 -o issue-42.md
```

## Build

Requirements:

- Linux or WSL2
- Python 3.11+
- `uv`
- Git

Build package artifacts:

```bash
uv sync --frozen --all-groups
uv build
```

The wheel and source distribution are written to `dist/`.

## Configure

Credentials are stored in the OS user config directory, not in this repo.

```bash
uv run secanalyzer --set-token github
uv run secanalyzer --set-token llm --provider claude
uv run secanalyzer --api-key-status
```

Use `--provider gemini` for Google AI Studio keys.

## Monitor

The final release includes local JSONL operational logs. Logs track command starts/failures, scan counts, redaction hits, Bandit results, GitHub/LLM errors, and LLM retry events.

Choose a log file:

```bash
SECANALYZER_LOG_FILE=./operations.jsonl uv run secanalyzer --scan .
```

Disable logs:

```bash
SECANALYZER_LOG_DISABLE=1 uv run secanalyzer --help
```

## Security

The main security controls are path confinement, extension allowlisting, secret redaction, LLM pre-send blocking, schema validation, local-only credential storage, Bandit, `pip-audit`, and local operational logging.

Details:

- [Security policy](docs/SECURITY.md)
- [Security report](docs/SECURITY_REPORT.md)

## Documentation

Please refer to the detailed deployment guide for a deeper dive into the internals:

- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)
