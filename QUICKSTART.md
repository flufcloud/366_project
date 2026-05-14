# Quickstart — secanalyzer

This guide walks you from **zero** to running **`--scan`** and **`--issues`** on your machine. Commands assume a Unix-style shell (**Linux**, **macOS**, or **WSL** on Windows).

---

## 1. What you need installed

| Requirement | Notes |
|---------------|--------|
| **[uv](https://docs.astral.sh/uv/)** | Package manager and virtualenv (install: `curl -LsSf https://astral.sh/uv/install.sh \| sh` on Linux/macOS, or see uv docs for Windows). |
| **Git** | To clone this repository. |
| **Network** | For `uv` downloads, GitHub API, and LLM APIs when you use `--issues`. |

You do **not** need a system-wide Python 3.11 first: `uv` can install the version pinned in [`.python-version`](.python-version) into the project when you sync.

### Windows (WSL)

Use **Ubuntu** (or another distro) in WSL2, then open a terminal and go to the project. If the repo lives on the Windows drive, paths look like:

```bash
cd /mnt/c/Users/<You>/Desktop/academic/366/366_project
```

All commands below are run from the **repository root** (`366_project`).

---

## 2. Install the tool (one-time per clone)

From the repository root:

```bash
uv sync --all-groups
```

This creates **`.venv/`** in this folder, installs dependencies from **[`uv.lock`](uv.lock)**, and installs the `secanalyzer` package into that environment.

**Sanity check:**

```bash
uv run secanalyzer --help
```

You should see usage for flags like `--scan`, `--issues`, `--set-token`, etc.

---

## 3. Store credentials (one-time per machine user)

Credentials are stored under your OS **user config directory** (not in the git repo). For tests only, you can override with `SECANALYZER_CONFIG_DIR`; otherwise ignore that variable.

### 3a. GitHub token (required for `--issues`)

1. Create a **Personal Access Token** at [github.com/settings/tokens](https://github.com/settings/tokens) with at least the **`repo`** scope (so private repos you can access work too, if needed).
2. From the project root, run:

   ```bash
   uv run secanalyzer --set-token github
   ```

3. When prompted, **paste the token** (input is hidden). Press Enter.

### 3b. LLM API key (required for `--issues`)

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

**What you get:** A Markdown report with an allowlisted file index, redacted snippets where patterns look like secrets, and notes. If redaction ran, you will see a **`[WARNING]`** line on stderr.

**No GitHub or LLM keys are required** for `--scan` only.

---

## 6. Analyze open GitHub issues and PRs (interactive)

**Requirements:** Sections 3–4 completed successfully.

```bash
uv run secanalyzer --issues YOUR_GITHUB_LOGIN/YOUR_REPO_NAME
```

Example:

```bash
uv run secanalyzer --issues octocat/Hello-World
```

**What happens:**

1. The tool lists **open** issues and pull requests from the GitHub API.
2. A **keyboard** menu appears (↑ / ↓, **Enter** to choose).
3. **Esc** cancels the menu and exits the issues loop (clean exit).
4. For a **pull request**, truncated patch text may be included in the LLM context.
5. The model returns **JSON** (risk level, justification, suggested mitigation, optional file/line hints). The tool validates it and prints a readable summary to **stdout**.

**`--provider` with `--issues`:** Optional. If you use it, it must match the vendor you stored with `--set-token llm` (**`claude`** / **`gemini`** / **`anthropic`** as alias for claude). Example:

```bash
uv run secanalyzer --issues org/repo --provider claude
```

---

## 7. Everyday commands (cheat sheet)

| Goal | Command |
|------|---------|
| Help | `uv run secanalyzer --help` |
| Version | `uv run secanalyzer --version` |
| Scan → stdout | `uv run secanalyzer --scan PATH` |
| Scan → file | `uv run secanalyzer --scan PATH -o report.md` |
| Issues / PRs | `uv run secanalyzer --issues owner/repo` |
| Check tokens | `uv run secanalyzer --api-key-status` |

Alternative without typing `uv run` every time:

```bash
source .venv/bin/activate
secanalyzer --scan .
```

---

## 8. Optional: model IDs (advanced)

If the default models are wrong for your account, set environment variables for that shell session (see [AGENTS.md](AGENTS.md) for defaults):

```bash
export SECANALYZER_ANTHROPIC_MODEL=claude-3-5-haiku-20241022
export SECANALYZER_GEMINI_MODEL=gemini-2.0-flash
```

---

## 9. Where to read more

| Document | Purpose |
|----------|---------|
| [README.md](README.md) | Full feature list, CLI table, troubleshooting |
| [SECURITY.md](SECURITY.md) | What data may go to LLMs, reporting vulnerabilities |
| [AGENTS.md](AGENTS.md) | Architecture, phases, CI, test-only env vars |

If something fails, start with **`--help`**, then **`--api-key-status`**, then the [Troubleshooting](README.md#troubleshooting) section in the README.
