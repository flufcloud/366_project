# Security Report — Threat Model vs. Implementation

**Audience:** Security review or course presentation tying **documented threats** to **concrete controls** in code and process.  
**Basis:** The project’s formal threat catalog (six attacks, DFD surface points **A1–A7**) and the shipped implementation under [`src/secanalyzer/`](../src/secanalyzer/).

This report maps each **cataloged attack** to **design goals**, **where it is mitigated in code or CI**, and **residual risk**.

---

## 1. Trust boundaries and attack surface (DFD recap)

| ID | Surface | Description |
|----|---------|-------------|
| **A1** | CLI arguments | Repository path, flags, owner/repo strings. |
| **A2** | Repository contents | Files read during `--scan`; symlink and path semantics. |
| **A3** | GitHub issue/PR data | Titles, bodies, patch hunks from REST API. |
| **A4** | LLM prompt assembly | Combined system + user text before vendor API. |
| **A5** | LLM response handling | Parsed JSON shown to user. |
| **A6** | Credential storage | PAT and LLM key files on disk and in memory during HTTP. |
| **A7** | Security artifacts | Final reports, issue logs, and validation evidence that describe system weaknesses. |

External trust boundaries: **GitHub REST API**, **Anthropic / Google LLM APIs**.

---

## 2. Summary matrix (attacks → mitigations → implementation)

| Attack (catalog) | Primary STRIDE themes | Mitigation goal | Implementation evidence | Residual risk |
|------------------|----------------------|-----------------|---------------------------|---------------|
| **1** Prompt injection via issue/PR | Spoofing, Tampering | Isolate untrusted text; validate model output structure | Delimited `SECANALYZER_USER_CONTROLLED_DATA_*` blocks + strict system instructions; **JSON schema** validation on model output ([`llm.py`](../src/secanalyzer/llm.py)) | Prompt injection is **not fully solvable**; malicious content can still bias models or cause refusal loops. |
| **2** Credential leakage via logs/stdout | Information disclosure | Never echo secrets; no raw traces; no keys in prompts | `getpass` for token entry; errors via **`UserFacingError`** strings ([`cli.py`](../src/secanalyzer/cli.py)); keys only in HTTP headers/query ([`github_client.py`](../src/secanalyzer/github_client.py), [`llm.py`](../src/secanalyzer/llm.py)) | Compromised workstation or dependency could still read config files or memory outside this app’s control model. |
| **3** Path traversal / shell injection | Elevation, Tampering | Confine reads; no shell with filenames | `Path.resolve`, `relative_to` root check; `os.walk(..., followlinks=False)`; no subprocess shell for scan ([`repo_analyzer.py`](../src/secanalyzer/repo_analyzer.py)) | Logic bugs in path handling; TOCTOU on unusual FS layouts—**defense in depth** still recommended (run in disposable VM for hostile trees). |
| **4** Sensitive code / PII to LLM vendor | Information disclosure | Minimize payload; redact; abort if secrets in outbound prompt | **`redact_text`** on repo scan output; **pre-send** `redact_text` on **full** assembled LLM prompt with **abort on any hit** ([`llm.py`](../src/secanalyzer/llm.py)); truncation warnings; PR patch caps ([`github_client.py`](../src/secanalyzer/github_client.py)); **`--scan`** narrative uses **bounded inventory** only ([`build_scan_inventory_for_llm`](../src/secanalyzer/repo_analyzer.py)) — no full-repo paste by default | Heuristic redaction **misses novel secret formats**; users may still send proprietary logic intentionally—**policy** and **vendor terms** matter. |
| **5** Dependency / supply chain compromise | Tampering | Pin versions; audit on CI | **`uv.lock`** + **`uv sync --frozen`** in CI ([`ci.yml`](../.github/workflows/ci.yml)); **`pip-audit`** in CI and dev group; **`bandit`** static analysis | Lockfile compromise, compromised PyPI package **not** covered by app runtime alone; org should review PRs that touch `uv.lock`. |
| **6** Security report theft | Information disclosure | Treat final security artifacts as controlled release materials | Final report is versioned with the codebase, avoids secrets, and records accepted risks in [ISSUE_LOG.md](ISSUE_LOG.md) instead of hidden notes | If stolen or separated from the release context, the report can help attackers prioritize known gaps. |

---

## 3. Per-attack analysis (detailed)

### Attack 1 — Prompt injection via PR/issue content (A3, A4)

**Threat:** Attacker-controlled issue/PR text embeds instructions (e.g. “ignore prior rules”, “print secrets”) to manipulate the model or downstream presentation.

**Mitigations implemented:**

1. **Structural separation:** GitHub-sourced strings are placed only inside **`<<<SECANALYZER_USER_CONTROLLED_DATA_BEGIN>>>…END>>>`** with system text instructing the model to treat that region as **inert data** ([`build_issue_analysis_prompts`](../src/secanalyzer/llm.py)).
2. **Output contract:** The model must return a **single JSON object** with fixed keys; **schema validation** rejects malformed or incomplete structures before presenting as a finished report ([`validate_analysis_schema`](../src/secanalyzer/llm.py)).
3. **Scan narrative:** For repository summaries, GitHub-free inventory text is wrapped in **`SECANALYZER_SCAN_INVENTORY_*`** delimiters with instructions to treat it as untrusted facts ([`generate_repo_scan_markdown`](../src/secanalyzer/llm.py)).

**Residual risk:** Delimiter discipline is **not a cryptographic guarantee**. Strong models may still partially comply with malicious instructions; integrity of “risk_level” is **best-effort**, not audited by a second authority.

---

### Attack 2 — Credential leakage via logs, stderr, or prompts (A6, A4)

**Threat:** Tokens appear in exceptions, debug logs, or are accidentally concatenated into LLM bodies.

**Mitigations implemented:**

1. **Storage isolation:** Keys written under user config dir; file permissions tightened on Unix where supported ([`config.py`](../src/secanalyzer/config.py)).
2. **No success-path echo:** Token setup uses **`getpass`**; success messages do not repeat secrets ([`cli.py`](../src/secanalyzer/cli.py)).
3. **Pre-send gate:** Before HTTP to LLM, the **entire** system+user prompt string is scanned with the same **regex family** as scan redaction; **any match aborts** the request ([`assert_prompt_passes_presend_filter`](../src/secanalyzer/llm.py)).
4. **User-facing errors:** `UserFacingError` / `LLMError` / `GitHubApiError` carry **short messages**; stack traces are not printed to the user by design in the CLI path.

**Residual risk:** If a **future** code path logs full HTTP payloads or prompts, regression is possible—**CI bandit** and code review should flag new logging.

---

### Attack 3 — Path traversal and shell injection (A1, A2)

**Threat:** Malicious repo layout or filenames escape the intended root or invoke a shell.

**Mitigations implemented:**

1. **Root resolution and membership:** Files must **`relative_to`** the resolved scan root ([`scan_repository`](../src/secanalyzer/repo_analyzer.py)).
2. **No symlink follow on walk:** `os.walk(..., followlinks=False)` reduces symlink-based escapes into sibling trees.
3. **No shell:** Scanning does not spawn a shell with path components as command fragments.

**Residual risk:** Exotic filesystem behaviors; **Windows vs. WSL** path edge cases when sharing a single working copy—operational guidance in [QUICKSTART.md](QUICKSTART.md).

---

### Attack 4 — Unintended sensitive data exfiltration to LLM vendor (A2, A4)

**Threat:** Large or sensitive bodies cross the vendor trust boundary without user understanding.

**Mitigations implemented:**

1. **Allowlist + size caps:** Extensions gate what is read; per-file **snippet byte cap** in scan; PR patches **truncated per file** and **total** cap in GitHub fetch ([`repo_analyzer.py`](../src/secanalyzer/repo_analyzer.py), [`github_client.py`](../src/secanalyzer/github_client.py)).
2. **Token budget:** Estimated-token ceiling (~**100k**) with **truncation** of the user block and stderr **warning** ([`enforce_prompt_token_budget`](../src/secanalyzer/llm.py)).
3. **Redaction + abort:** Scan path redacts for reporting; LLM path **aborts** if outbound text still matches secret-like patterns ([`redact_text`](../src/secanalyzer/repo_analyzer.py) reused from [`llm.py`](../src/secanalyzer/llm.py)).
4. **`--scan` narrative scope:** When an LLM is used for scan output, only a **capped path list** and **small excerpts** are placed inside **`SECANALYZER_SCAN_INVENTORY_*`** delimiters for [`generate_repo_scan_markdown`](../src/secanalyzer/llm.py); the default Markdown report **does not** embed every source line.
5. **Transparency:** [SECURITY.md](SECURITY.md), [QUICKSTART.md](QUICKSTART.md), and [docs/SECURITY_REPORT.md](SECURITY_REPORT.md) describe what crosses the vendor boundary.

**Residual risk:** **False negatives** on regex; **business logic** and **comments** without secret-like syntax still leave the org; users must **assume vendor retention policies** apply.

---

### Attack 5 — Dependency confusion / supply chain (install-time, pre-runtime)

**Threat:** Malicious or vulnerable dependencies undermine the tool before its controls run.

**Mitigations implemented:**

1. **Locked graph:** **`uv.lock`** pins transitive versions; CI uses **`uv sync --frozen --all-groups`** ([`ci.yml`](../.github/workflows/ci.yml)).
2. **Vulnerability scan:** **`pip-audit`** in CI and locally.
3. **Static analysis:** **`bandit`** over `src/secanalyzer` in CI ([`pyproject.toml`](../pyproject.toml) `[tool.bandit]`).

**Residual risk:** **Zero-day** in dependencies; **compromised lockfile PR**; pip-audit does not deeply audit **non-PyPI** editable install of `secanalyzer` itself (expected skip). Organizational **SBOM** and **merge policies** remain important.

---

### Attack 6 — Security report theft (A7)

**Threat:** An attacker steals or obtains the final codebase security report and uses its threat mappings, accepted risks, and validation evidence to focus attacks.

**Mitigations implemented:** The report is treated as a controlled security artifact: it is versioned with the final codebase, contains no credentials, and points residual risks to [ISSUE_LOG.md](ISSUE_LOG.md) so maintainers can track them formally.

**Residual risk:** The report still reveals useful attacker context. If shared outside the intended audience, it can reduce reconnaissance time.

---

## 4. Response handling (A5)

**Threat:** Model returns malicious or misleading free text executed as code.

**Control:** No **`eval`** on model output; only **JSON parse** + **typed field checks**; presentation is **string templating** into Markdown sections ([`render_analysis_markdown`](../src/secanalyzer/issues_session.py)).

**Residual risk:** Social engineering in displayed “suggested_mitigation” text—users should treat output as **advisory**, not auto-patched code.

---

## 5. Process and documentation controls

| Control | Location |
|---------|----------|
| Vulnerability disclosure process | [SECURITY.md](SECURITY.md) |
| CI security gates | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) |
| Data classification for LLM | [SECURITY.md](SECURITY.md) “What may / must not be sent” |
| First-run operational safety | [QUICKSTART.md](QUICKSTART.md) (venv OS mismatch) |
| Local operational logging | [`operations.py`](../src/secanalyzer/operations.py), [SECURITY.md](SECURITY.md) “Operational logging” |

---

## 6. Conclusion for presentations

1. **Defense in depth:** Path rules + redaction + delimiter prompts + schema validation + pre-send abort + locked deps + CI audits each address **different** failure modes; none alone is sufficient.
2. **Explicit limitations:** **Prompt injection** and **regex redaction completeness** remain industry-wide limitations—communicate these honestly in slides.
3. **Evidence-based claims:** When presenting, cite **modules** (`llm.py`, `repo_analyzer.py`, `config.py`) and **CI** for auditors who want traceability from threat row to artifact.

---

## 7. Cross-reference to architecture

For component-level diagrams and data flows, see **[TECHNICAL_REPORT.md](TECHNICAL_REPORT.md)**.

---

*This security report interprets the cataloged threat model in terms of the current repository implementation; drift between documentation and code should be re-checked after substantive merges.*
