# Final Written Report

Project: **AI-Powered Codebase Security Analyzer (`secanalyzer`)**  
Repository: [https://github.com/flufcloud/366_project](https://github.com/flufcloud/366_project)

## Executive summary

`secanalyzer` is a local command-line tool that helps developers and security engineers understand the security posture of a codebase. It scans a repository, produces a structured Markdown inventory, runs static analysis, optionally generates an LLM-assisted security report, and can analyze GitHub issues or pull requests for security relevance.

The final release is production-ready for the course scope. It includes a clean Python package layout, reproducible dependency management with `uv`, a pytest suite, static security checks, dependency auditing, local operational logging, security documentation, deployment instructions, and a formal issue log for accepted risks.

The most important design decision was to keep the system local and explicit. The user chooses when to scan a repository, when to call GitHub, and when to send bounded content to an LLM provider. This keeps the tool useful while respecting the main security concern identified during threat modeling: accidental exposure of credentials or sensitive source code.

## Project lifecycle and prior deliverables

The project evolved through five milestones.

| Milestone | Role in final system | Detailed artifact |
|-----------|----------------------|-------------------|
| M1 | Initial proposal and project direction. The idea was narrowed into a feasible local security-analysis CLI. | No separate M1 file is present in the repository; the final direction is reflected in M2. |
| M2 | Agile requirements, MVP scope, user stories, non-functional requirements, and risk backlog. | `docs/reports/M2_Agile_Requirements.md` |
| M3 | Architecture, data flow, threat modeling, STRIDE-style security analysis, and mitigations. | `docs/reports/M3_Design_Document_ThreatModeling.md` |
| M4 | Beta release report with implementation state, CI/CD setup, testing, and security scan evidence. | `docs/reports/M4_Beta_Release_Report.md` |
| M5 | Final hardening, operational logging, deployment documentation, issue log, and final validation. | `docs/reports/M5_Final_Release_Report.md` |

### Pivot from the first proposal

The initial project direction was broader than the final release target. The original intent was to use modern AI to help developers understand and evaluate security risks in code, but the scope could easily have expanded into a large general-purpose AI security platform. During requirements and design work, the project pivoted into a narrower local CLI with three core capabilities: repository scanning, GitHub issue/PR triage, and LLM-assisted security reporting.

That pivot was necessary for three reasons:

- **Security:** A local CLI has clearer trust boundaries than a hosted service. It reduces the risk of server-side data retention, multi-user secrets handling, and accidental broad telemetry.
- **Reliability:** A focused CLI could be tested with deterministic unit tests and mocked network calls.
- **Schedule:** The course timeline required a complete, demonstrable system. Narrowing the scope made it possible to finish core functionality, CI, documentation, and final hardening.

The pivot improved the final result. Instead of delivering a vague AI assistant, the final project delivers a concrete tool with explicit inputs, outputs, controls, and validation evidence.

## System overview

The final system is organized around these components:

| Component | Module | Responsibility |
|-----------|--------|----------------|
| CLI interface | `src/secanalyzer/cli.py` | Parses flags, routes actions, handles expected errors without raw tracebacks. |
| Config manager | `src/secanalyzer/config.py` | Stores GitHub and LLM credentials outside the repository and validates key shape. |
| Repository analyzer | `src/secanalyzer/repo_analyzer.py` | Walks repository trees safely, applies extension allowlists, redacts secrets, builds scan reports. |
| Bandit integration | `src/secanalyzer/bandit_scan.py` | Runs static Python security analysis and summarizes results in scan output. |
| GitHub client | `src/secanalyzer/github_client.py` | Fetches open issues, PRs, comments, and bounded PR file summaries. |
| LLM orchestration | `src/secanalyzer/llm.py`, `src/secanalyzer/scan_llm.py` | Builds prompts, enforces token budgets, redacts outbound prompts, retries provider calls, validates outputs. |
| Issue session glue | `src/secanalyzer/issues_session.py` | Connects GitHub data, optional report context, and LLM analysis. |
| Output handler | `src/secanalyzer/output.py` | Writes Markdown to stdout or files. |
| Operations logging | `src/secanalyzer/operations.py` | Records sanitized local JSONL events for monitoring, errors, and security events. |

The deployment model is intentionally simple: one user runs one local CLI process. There is no hosted backend, database, web server, or background daemon.

## Methodology and security posture

The security methodology comes from the M3 threat model. The project identified six attack surfaces:

- A1: CLI arguments and repository path input
- A2: repository file contents
- A3: GitHub issue/PR metadata and comments
- A4: LLM prompt construction
- A5: LLM response parsing and rendering
- A6: credential storage and retrieval

Five primary threat categories were identified:

1. Prompt injection through issue or PR content.
2. Credential leakage through logs, stdout, errors, or prompts.
3. Path traversal or shell injection through repository files.
4. Sensitive code or private data exfiltration to an LLM provider.
5. Dependency confusion or supply-chain compromise.

The final release mitigates these with defense in depth:

- repository paths are resolved and scanned with `followlinks=False`;
- file extensions are allowlisted;
- binary and non-UTF-8 content is skipped;
- secret-like strings are redacted;
- outbound LLM prompts are scanned again and blocked if credential-shaped patterns remain;
- GitHub/user-controlled text is wrapped in explicit untrusted-data delimiters;
- structured LLM outputs are schema-validated before rendering;
- expected failures are shown as user-facing messages, not raw stacktraces;
- dependencies are pinned in `uv.lock`;
- CI runs pytest, Bandit, and `pip-audit`;
- local operations logs record behavior without remote telemetry.

### Final security report as a security artifact

One important final security artifact is the generated security report itself. The purpose of `secanalyzer` is not only to run checks; it also produces a written security report for a codebase. That report becomes a security component because it records:

- what was scanned;
- which files and trust boundaries appear important;
- what redactions occurred;
- which static-analysis findings exist;
- which risks require human review;
- what evidence supported the conclusions.

In practice, this kind of report helps security work become repeatable. It gives reviewers, developers, and future maintainers a shared artifact for audit, handoff, presentation, and follow-up issue creation. The generated report is not a replacement for expert review, but it is a concrete security artifact that improves visibility and accountability.

## Evaluation and final results

The final evaluation used automated tests, static analysis, dependency auditing, and CLI smoke tests.

| Evaluation method | Result | Purpose |
|-------------------|--------|---------|
| pytest | 99 passed, 1 skipped | Validates CLI behavior, config handling, scanner behavior, GitHub client behavior, LLM prompt and parsing logic, report tree behavior. |
| Bandit | No issues identified | Checks production Python source for common security problems. |
| pip-audit | No known vulnerabilities found | Checks locked dependency set against known vulnerability databases. |
| CLI help smoke test | Passed | Confirms package entrypoint and argument parser are usable. |
| Static scan smoke test | Passed | Confirms `--scan .` completes, writes Markdown, logs events, and reports 0 embedded Bandit issues for production source. |

The final release also fixed a practical evaluation problem found during smoke testing: the embedded Bandit scan originally reported noise from virtualenv/test paths when scanning the project root. That was hardened so production scan output excludes `.venv`, build artifacts, and tests. This made the tool's own scan output more accurate and presentation-ready.

## CI/CD pipeline

The GitHub Actions pipeline is defined in `.github/workflows/ci.yml`.

It runs on pushes and pull requests to `main` or `master`:

```bash
uv sync --frozen --all-groups
uv run pytest
uv run bandit -r src/secanalyzer
uv run pip-audit
```

The pipeline helped development in three ways:

- **Repeatability:** `uv sync --frozen` ensures the lockfile is the source of truth.
- **Regression control:** pytest catches changes that break scanner, config, GitHub, or LLM orchestration behavior.
- **Security gatekeeping:** Bandit and `pip-audit` prevent known static-analysis and dependency issues from being ignored.

## Operations and monitoring

Final release operations were improved with local JSONL logging. The logger records:

- command start/completion/failure;
- scan starts and completions;
- redaction hits;
- Bandit result counts;
- GitHub request failures and invalid JSON responses;
- LLM request starts/completions;
- LLM rate-limit and server-error retries;
- LLM pre-send security blocks.

The logs are local, not remote telemetry. They are meant for debugging, demonstration, and operational evidence. Token-like fields are redacted by field name, and prompt bodies are not logged.

## Challenges and how they were addressed

### Scope control

The largest project risk was scope creep. An AI security assistant can become very broad quickly: full code indexing, hosted dashboards, continuous monitoring, auto-patching, and multi-user collaboration were all tempting directions. The project addressed this by enforcing the M2 MVP: repository scan, GitHub work-item analysis, and preliminary mitigation suggestions.

### LLM safety and prompt injection

Prompt injection cannot be fully solved. The project addressed this by treating GitHub and repository content as untrusted data, wrapping it in delimiter blocks, validating structured outputs, and documenting residual risk in the issue log.

### Credential and data exposure

The tool handles GitHub tokens, LLM keys, source files, and issue text. The project addressed this through local config storage, hidden token input, redaction, pre-send LLM blocking, no raw tracebacks in expected CLI failures, and documentation of what may cross vendor boundaries.

### LLM rate limits

Google/Gemini rate limiting became a concrete reliability problem. The tool added retries, model configuration, model-listing support, environment controls, and a formal GitHub issue for future rate-limit hardening.

### Final-release polish

The beta was functional, but final release required better organization and operations. Documentation was reorganized into guides and reports, a deployment guide was added, issue logs were formalized, and operational logging was implemented.

## Roadmap

Outstanding non-critical work is documented in `deliverables/ISSUE_LOG.md` and `issues/`.

Priority roadmap items:

1. Add an adversarial prompt-injection evaluation suite.
2. Replace regex-only secret detection with a stronger local scanner or entropy heuristic.
3. Add supply-chain provenance checks or SBOM generation.
4. Continue improving LLM rate-limit handling and provider fallback.
5. Add more end-to-end demo fixtures for hostile repository layouts and malicious issue content.

## Concluding engineering analysis

The final system is intentionally modest but complete. Its strongest engineering quality is that it treats AI as an optional analysis layer around deterministic security controls, not as a trusted authority. The deterministic parts handle path confinement, filtering, redaction, static analysis, config, and logging. The LLM parts produce summaries and triage guidance, but outputs remain advisory.

The main takeaway for future projects is that AI-assisted security tools need strong boundaries. The hard part is not only asking a model useful questions; it is deciding what data should reach the model, what the model is allowed to influence, what evidence should be logged, and what residual risks must be disclosed. This project became better when it narrowed its scope and made those boundaries explicit.
