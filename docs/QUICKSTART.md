# Quickstart — secanalyzer

This guide walks you from **zero** to running **`--scan`** and GitHub issue analysis on your machine. Commands assume a Unix-style shell (**Linux**, **macOS**, or **WSL** on Windows).

---

## 1. What you need installed

| Requirement | Notes |
|---------------|--------|
| **[uv](https://docs.astral.sh/uv/)** | Package manager and virtualenv (install: `curl -LsSf https://astral.sh/uv/install.sh \| sh` on Linux/macOS, or see uv docs for Windows). |
| **Git** | To clone this repository. |
| **Network** | For `uv` downloads, GitHub API, and LLM APIs when you use `--analyze-issue`. |

You do **not** need a system-wide Python 3.11 first: `uv` can install the version pinned in [`.python-version`](../.python-version) into the project when you sync.

### Windows (WSL)

Use **Ubuntu** (or another distro) in WSL2, then open a terminal and go to the project. If the repo lives on the Windows drive, paths look like:

```bash
cd /mnt/c/Users/<You>/Desktop/academic/366/366_project
```

All commands below are run from the **repository root** (`366_project`).

**If you already ran `uv sync` from Windows PowerShell or CMD:** the `.venv` folder is a **Windows** virtualenv (`Scripts/`, not Linux `bin/`). WSL cannot use it. Remove it once, then sync inside WSL:

```bash
rm -rf .venv
uv sync --all-groups
```

If you later use **both** Windows and WSL on the same clone, use **separate clones** (e.g. one on `%USERPROFILE%\projects\` and one under `~/projects` in the Linux filesystem), or delete `.venv` each time you switch OS so `uv` can recreate the right layout.

---

## 2. Install the tool (one-time per clone)

From the repository root:

```bash
uv sync --all-groups
```

This creates **`.venv/`** in this folder, installs dependencies from **[`uv.lock`](../uv.lock)**, and installs the `secanalyzer` package into that environment.

**Sanity check:**

```bash
uv run secanalyzer --help
```

You should see usage for flags like `--scan`, `--list-issues`, `--analyze-issue`, `--set-token`, etc.

---

## 3. Store credentials (one-time per machine user)

Credentials are stored under your OS **user config directory** (not in the git repo). For tests only, you can override with `SECANALYZER_CONFIG_DIR`; otherwise ignore that variable.

### 3a. GitHub token (required for `--list-issues` / `--analyze-issue`)

1. Create a **Personal Access Token** at [github.com/settings/tokens](https://github.com/settings/tokens) with at least the **`repo`** scope (so private repos you can access work too, if needed).
2. From the project root, run:

   ```bash
   uv run secanalyzer --set-token github
   ```

3. When prompted, **paste the token** (input is hidden). Press Enter.

### 3b. LLM API key (required for `--analyze-issue`)

You need either **Anthropic (Claude)** or **Google (Gemini)** credentials, matching what you configure below.

**Claude (Anthropic):**

```bash
uv run secanalyzer --set-token llm --provider claude
```

Paste a key that starts with **`sk-ant-`** when prompted.

**Gemini (Google AI Studio):**

```bash
uv run secanalyzer --set-token llm --provider gemini
```

Paste a key that starts with **`AIza`** when prompted.

You can also use `--provider anthropic`; it is stored the same as **claude** for API routing.

---

## 4. Verify keys

```bash
uv run secanalyzer --api-key-status
```

- **`[OK]`** lines mean that credential is present and (for GitHub) accepted by the API; for the LLM key, format is validated (live LLM ping is not required for this check).
- **`[MISSING]`** or **`[BAD]`** means you should repeat section 3 for that credential.

Exit code **`0`** only when **both** GitHub and LLM checks pass. **`1`** means fix tokens and run again.

---

## 5. Scan a local repository (Markdown report)

**Print Markdown to the terminal:**

```bash
uv run secanalyzer --scan /absolute/or/relative/path/to/repo
```

**Write Markdown to a file:**

```bash
uv run secanalyzer --scan /path/to/repo -o ./scan-report.md
```

**What you get:**

1. **Deterministic inventory** — Markdown table of allowlisted files (paths, sizes, line counts, redaction hit counts), plus scan metadata. **Full-file code dumps are not included** in the report (they were unusably long and not a substitute for a written assessment).

2. **LLM narrative (optional)** — If you completed **section 3b** (LLM API key), the tool sends only a **bounded snapshot** to the model (up to 200 paths, an extension histogram, and up to five small redacted excerpts of at most 1,200 characters each). The model is asked for a **concise security/architecture Markdown** section (about **1–4 printed pages** of prose). If no LLM key is stored, the report ends with a short note telling you how to enable the narrative.

If redaction ran during scanning, you will see a **`[WARNING]`** line on stderr.

**GitHub tokens are not** required for `--scan`. An **LLM key** is optional but recommended if you want the narrative section.

---

## 6. GitHub issues and PRs

**Requirements:** Sections 3–4 completed successfully.

**List open items (table to stdout):**

```bash
uv run secanalyzer --list-issues YOUR_GITHUB_LOGIN/YOUR_REPO_NAME
```

**Analyze one issue or PR:**

```bash
uv run secanalyzer --analyze-issue octocat/Hello-World --issue-number 42
uv run secanalyzer --analyze-issue org/repo --issue-number 7 -o issue-7.md --provider claude
```

**What happens:**

1. The tool fetches the issue/PR title, body, and comment thread from GitHub.
2. For a **pull request**, a truncated patch may be included.
3. The LLM returns a brief Markdown report: **Risk level**, **Security overview**, **Recommended actions**.
4. Optional: pass a prior **`--llm-report`** artifact directory with `--report-context` (and `--report-scope` for a subdirectory rolling summary).

```bash
uv run secanalyzer --analyze-issue org/repo --issue-number 42 \
  --report-context ./repo-llm-report --report-scope src/auth
```

---

## 7. Everyday commands (cheat sheet)

| Goal | Command |
|------|---------|
| Help | `uv run secanalyzer --help` |
| Version | `uv run secanalyzer --version` |
| Scan → stdout | `uv run secanalyzer --scan PATH` |
| Scan → file | `uv run secanalyzer --scan PATH -o report.md` |
| List issues / PRs | `uv run secanalyzer --list-issues owner/repo` |
| Analyze one issue | `uv run secanalyzer --analyze-issue owner/repo --issue-number N` |
| Check tokens | `uv run secanalyzer --api-key-status` |

Alternative without typing `uv run` every time:

```bash
source .venv/bin/activate
secanalyzer --scan .
```

---

## 8. Optional: model IDs (advanced)

If the default models are wrong for your account, set environment variables for that shell session:

```bash
export SECANALYZER_ANTHROPIC_MODEL=claude-3-5-haiku-20241022
export SECANALYZER_GEMMA_MODEL=gemma-3-12b-it
# Or: export SECANALYZER_GEMINI_MODEL=gemini-2.5-flash
```

---

## 9. Where to read more

| Document | Purpose |
|----------|---------|
| [README.md](../README.md) | Concise project quickstart |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Full build, install, release, and operational checklist |
| [SECURITY.md](SECURITY.md) | What data may go to LLMs, reporting vulnerabilities |

If something fails, start with **`--help`**, then **`--api-key-status`**, then review the relevant setup section in [DEPLOYMENT.md](DEPLOYMENT.md).
