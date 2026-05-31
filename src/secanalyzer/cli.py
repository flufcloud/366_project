"""CLI entry point: parse arguments, route subcommands, and surface errors without raw tracebacks."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path
from typing import Sequence

from secanalyzer import operations
from secanalyzer.exceptions import UserFacingError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secanalyzer",
        description=(
            "Local CLI to document a codebase and analyze GitHub issues/PRs with LLM assistance."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s { _package_version() }",
    )
    parser.add_argument(
        "--scan",
        metavar="PATH",
        help="Static repository scan: Markdown inventory only (no LLM).",
    )
    parser.add_argument(
        "--llm-report",
        metavar="PATH",
        help="LLM security report: analyze each source file, compact context, synthesize Markdown.",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="With --scan or --llm-report, write Markdown to FILE instead of stdout.",
    )
    parser.add_argument(
        "--report-dir",
        metavar="DIR",
        help=(
            "With --llm-report, write a hierarchical artifact tree (per-file reviews, "
            "compaction passes, synthesis). Default: <output-stem>.report-tree/ next to -o."
        ),
    )
    parser.add_argument(
        "--list-issues",
        metavar="OWNER/REPO",
        help="List open GitHub issues and pull requests (non-interactive table).",
    )
    parser.add_argument(
        "--analyze-issue",
        metavar="OWNER/REPO",
        help="Analyze one issue/PR with the LLM (brief security overview).",
    )
    parser.add_argument(
        "--issue-number",
        type=int,
        metavar="N",
        help="Issue or PR number (required with --analyze-issue).",
    )
    parser.add_argument(
        "--report-context",
        metavar="DIR",
        help=(
            "With --analyze-issue, path to an --llm-report artifact tree; "
            "adds rolling codebase summary to the prompt."
        ),
    )
    parser.add_argument(
        "--report-scope",
        metavar="PATH",
        help=(
            "With --analyze-issue and --report-context, repo-relative directory "
            "for compaction/by-directory rolling summary (e.g. apps/api). "
            "If omitted, uses final-rolling-summary or infers from PR files."
        ),
    )
    parser.add_argument(
        "--api-key-status",
        action="store_true",
        help="Check whether configured API keys are present and valid.",
    )
    parser.add_argument(
        "--test-llm",
        action="store_true",
        help="Send a minimal request to the configured LLM vendor to verify the API key.",
    )
    parser.add_argument(
        "--list-google-models",
        action="store_true",
        help="List Google AI models your API key can call (generateContent).",
    )
    parser.add_argument(
        "--google-model",
        metavar="MODEL",
        help=(
            "Google AI model id for this run (e.g. gemini-2.5-flash, gemma-3-27b-it). "
            "Overrides saved default and env vars."
        ),
    )
    parser.add_argument(
        "--set-google-model",
        metavar="MODEL",
        help="Save default Google model id in LLM config (requires provider gemini).",
    )
    parser.add_argument(
        "--set-token",
        choices=("github", "llm"),
        metavar="KIND",
        help="Securely store a GitHub or LLM credential.",
    )
    parser.add_argument(
        "--provider",
        metavar="NAME",
        help="With --set-token llm, choose vendor (claude, gemini, anthropic). With --analyze-issue, must match stored LLM vendor.",
    )
    return parser


def _package_version() -> str:
    from secanalyzer import __version__

    return __version__


def _mutating_actions(args: argparse.Namespace) -> list[str]:
    names: list[str] = []
    if args.set_token is not None:
        names.append("--set-token")
    if args.api_key_status:
        names.append("--api-key-status")
    if args.test_llm:
        names.append("--test-llm")
    if args.list_google_models:
        names.append("--list-google-models")
    if args.set_google_model is not None:
        names.append("--set-google-model")
    if args.scan is not None:
        names.append("--scan")
    if args.llm_report is not None:
        names.append("--llm-report")
    if args.list_issues is not None:
        names.append("--list-issues")
    if args.analyze_issue is not None:
        names.append("--analyze-issue")
    return names


def _run_set_google_model(model: str) -> int:
    from secanalyzer import config
    from secanalyzer.exceptions import ConfigurationError

    try:
        config.save_google_model(model)
    except ConfigurationError as e:
        raise UserFacingError(str(e)) from e
    operations.event("config.google_model_saved", provider="gemini", model=model.strip())
    sys.stderr.write(f"Default Google model saved: {model.strip()!r}\n")
    return 0


def _run_set_token(kind: str, provider: str | None) -> int:
    from secanalyzer import config
    from secanalyzer.exceptions import ConfigurationError

    if kind == "github":
        token = getpass.getpass("GitHub token (input hidden): ")
        try:
            config.save_github_token(token)
        except ConfigurationError as e:
            raise UserFacingError(str(e)) from e
        operations.security_event("credential.updated", kind="github")
        sys.stderr.write("GitHub token saved under secanalyzer config directory.\n")
        return 0

    prov = (provider or "").strip().lower()
    if not prov:
        sys.stderr.write("LLM provider [claude / gemini / anthropic]: ")
        sys.stderr.flush()
        prov = sys.stdin.readline().strip()
    if not prov:
        raise UserFacingError(
            "LLM provider is required. Example: secanalyzer --set-token llm --provider claude",
        )
    key = getpass.getpass("LLM API key (input hidden): ")
    try:
        config.save_llm_credentials(prov, key)
    except ConfigurationError as e:
        raise UserFacingError(str(e)) from e
    operations.security_event("credential.updated", kind="llm", provider=prov)
    sys.stderr.write("LLM credentials saved under secanalyzer config directory.\n")
    return 0


def _run_api_key_status() -> int:
    from secanalyzer import config
    from secanalyzer.exceptions import ConfigurationError

    operations.event("config.api_key_status_started")
    healthy = True

    g = config.load_github_token()
    if not g:
        healthy = False
        print("[MISSING] GitHub token — run: secanalyzer --set-token github")
    else:
        ok, msg = config.validate_github_token(g)
        if ok:
            print(f"[OK] GitHub token — {msg}")
        else:
            healthy = False
            print(f"[BAD] GitHub token — {msg}")

    try:
        ok, msg, prov = config.validate_llm_credentials_shape()
    except ConfigurationError as e:
        healthy = False
        print(f"[BAD] LLM API key — {e}")
    else:
        if prov is None:
            healthy = False
            print("[MISSING] LLM API key — run: secanalyzer --set-token llm --provider claude")
        elif not ok:
            healthy = False
            print(f"[BAD] LLM API key — {msg}")
        else:
            print(f"[OK] LLM API key — {msg} (provider: {prov})")
            if prov == "gemini":
                from secanalyzer import llm as llm_mod

                print(f"     Google model: {llm_mod.resolve_google_generative_model()!r}")

    exit_code = 0 if healthy else 1
    operations.event("config.api_key_status_completed", healthy=healthy, exit_code=exit_code)
    return exit_code


def _run_list_google_models() -> int:
    from secanalyzer import config
    from secanalyzer import llm as llm_mod
    from secanalyzer.exceptions import ConfigurationError, LLMError

    try:
        cfg = config.load_llm_config()
    except ConfigurationError as e:
        raise UserFacingError(str(e)) from e
    if cfg is None:
        raise UserFacingError(
            "LLM not configured. Run: secanalyzer --set-token llm --provider gemini",
        )
    provider, api_key = cfg
    if provider != "gemini":
        raise UserFacingError(
            "--list-google-models requires Google AI credentials "
            "(secanalyzer --set-token llm --provider gemini).",
        )
    try:
        models = llm_mod.list_google_generate_content_models(api_key)
    except LLMError as e:
        raise UserFacingError(str(e)) from e
    configured = llm_mod.resolve_google_generative_model()
    print(f"Model for this run: {configured}")
    print(f"Models supporting generateContent ({len(models)}):")
    for m in models:
        mark = " *" if m == configured else ""
        print(f"  {m}{mark}")
    if configured not in models:
        print(
            f"\n[NOTE] {configured!r} is NOT in the list — use "
            "secanalyzer --set-google-model MODEL or --google-model MODEL.",
            file=sys.stderr,
        )
        return 1
    return 0


def _run_test_llm() -> int:
    from secanalyzer import config
    from secanalyzer import llm as llm_mod
    from secanalyzer.exceptions import ConfigurationError, LLMError

    try:
        cfg = config.load_llm_config()
    except ConfigurationError as e:
        raise UserFacingError(str(e)) from e
    if cfg is None:
        raise UserFacingError(
            "LLM not configured. Run: secanalyzer --set-token llm --provider claude (or gemini).",
        )
    provider, api_key = cfg
    try:
        reply = llm_mod.ping_llm(provider, api_key)
    except LLMError as e:
        raise UserFacingError(str(e)) from e
    preview = reply.replace("\n", " ").strip()
    if len(preview) > 120:
        preview = preview[:117] + "..."
    model_note = ""
    if provider == "gemini":
        from secanalyzer import llm as llm_mod

        model_note = f", model={llm_mod.resolve_google_generative_model()!r}"
    print(f"[OK] LLM API reachable ({provider}{model_note}). Model reply: {preview!r}")
    return 0


def _run_scan(scan_path: str, output: str | None) -> int:
    from secanalyzer import bandit_scan
    from secanalyzer import output as outmod
    from secanalyzer import repo_analyzer
    from secanalyzer.exceptions import ScanError

    out_path = Path(output).expanduser() if output else None
    operations.event("scan.started", scan_path=scan_path, output=out_path)
    try:
        report = repo_analyzer.scan_repository(scan_path)
    except ScanError as e:
        raise UserFacingError(str(e)) from e

    if report.total_redactions > 0:
        operations.security_event(
            "scan.redactions_detected",
            scan_root=report.root,
            redaction_hits=report.total_redactions,
        )
        sys.stderr.write(
            "[WARNING] Content redacted before reporting: "
            f"{report.total_redactions} pattern match(es) in scanned files.\n",
        )

    bandit_section = ""
    bandit_result, bandit_skip = bandit_scan.run_bandit_on_tree(report.root)
    if bandit_result is not None:
        bandit_section = bandit_scan.bandit_metrics_markdown(bandit_result)
        operations.event(
            "scan.bandit_completed",
            scan_root=report.root,
            total_issues=bandit_result.total_issues,
            severity_high=bandit_result.severity_high,
            severity_medium=bandit_result.severity_medium,
            severity_low=bandit_result.severity_low,
            python_files_scanned=bandit_result.python_files_scanned,
        )
        sys.stderr.write(
            f"[INFO] Bandit: {bandit_result.total_issues} issue(s) "
            f"(HIGH={bandit_result.severity_high}, "
            f"MEDIUM={bandit_result.severity_medium}, "
            f"LOW={bandit_result.severity_low}) "
            f"across {bandit_result.python_files_scanned} Python file(s).\n",
        )
    elif bandit_skip:
        operations.event("scan.bandit_skipped", scan_root=report.root, reason=bandit_skip)
        bandit_section = (
            "## Static analysis (Bandit)\n\n"
            f"Bandit was not run: {bandit_skip}\n"
        )
        sys.stderr.write(f"[INFO] {bandit_skip}\n")

    md = repo_analyzer.report_to_markdown(
        report,
        include_full_file_snippets=False,
        bandit_section=bandit_section or None,
    )
    try:
        outmod.write_report(md, out_path)
    except OSError as e:
        raise UserFacingError(f"Could not write output: {e}") from e
    operations.event(
        "scan.completed",
        scan_root=report.root,
        files_matched=len(report.files),
        redaction_hits=report.total_redactions,
        output=out_path,
    )
    return 0


def _run_llm_report(
    scan_path: str,
    output: str | None,
    report_dir: str | None = None,
) -> int:
    from secanalyzer import config
    from secanalyzer import llm as llm_mod
    from secanalyzer import output as outmod
    from secanalyzer import repo_analyzer
    from secanalyzer import report_tree
    from secanalyzer import scan_llm
    from secanalyzer.exceptions import ConfigurationError, LLMError, ScanError

    try:
        llm_cfg = config.load_llm_config()
    except ConfigurationError as e:
        raise UserFacingError(str(e)) from e
    if llm_cfg is None:
        raise UserFacingError(
            "LLM not configured. Run: secanalyzer --set-token llm --provider claude (or gemini).",
        )
    provider, api_key = llm_cfg
    operations.event(
        "llm_report.started",
        scan_path=scan_path,
        output=output,
        report_dir=report_dir,
        provider=provider,
    )
    if provider == "gemini":
        try:
            llm_mod.assert_google_model_available(api_key)
        except LLMError as e:
            raise UserFacingError(str(e)) from e

    out_path = Path(output).expanduser() if output else None
    tree_path = report_tree.resolve_report_tree_dir(report_dir, out_path)
    tree_writer = report_tree.ReportTreeWriter(tree_path) if tree_path else None
    try:
        report = repo_analyzer.scan_repository(scan_path)
    except ScanError as e:
        raise UserFacingError(str(e)) from e

    if report.total_redactions > 0:
        operations.security_event(
            "llm_report.redactions_detected",
            scan_root=report.root,
            redaction_hits=report.total_redactions,
        )
        sys.stderr.write(
            "[WARNING] Content redacted before LLM analysis: "
            f"{report.total_redactions} pattern match(es).\n",
        )

    analyzable = scan_llm.llm_analyzable_files(report)
    est_calls = scan_llm.estimate_llm_report_api_calls(len(analyzable))
    operations.event(
        "llm_report.plan",
        scan_root=report.root,
        provider=provider,
        files_analyzable=len(analyzable),
        estimated_api_calls=est_calls,
        report_tree=tree_path,
    )
    tree_note = (
        f" Artifact tree: `{tree_path}`."
        if tree_writer is not None
        else " (use -o FILE or --report-dir DIR for a hierarchical artifact tree)."
    )
    sys.stderr.write(
        f"[INFO] LLM report: {len(analyzable)} file(s), ~{est_calls} API calls.{tree_note} "
        "Compaction/synthesis use bounded context (see SECANALYZER_LLM_ROLLING_MAX_TOKENS). "
        "HTTP 500 retries: SECANALYZER_LLM_SERVER_ERROR_MAX_RETRIES (default 30). "
        "Compaction/synthesis step retries: SECANALYZER_LLM_STEP_MAX_RETRIES (default 30). "
        "Optional pause between calls: SECANALYZER_LLM_BATCH_DELAY_SEC.\n",
    )
    sys.stderr.flush()

    def progress(msg: str) -> None:
        sys.stderr.write(msg + "\n")
        sys.stderr.flush()

    try:
        md, llm_warns = scan_llm.generate_llm_security_report(
            provider,
            api_key,
            report,
            progress=progress,
            report_tree=tree_writer,
        )
    except LLMError as e:
        raise UserFacingError(str(e)) from e

    for w in llm_warns:
        sys.stderr.write(f"[WARNING] {w}\n")

    try:
        outmod.write_report(md, out_path)
    except OSError as e:
        raise UserFacingError(f"Could not write output: {e}") from e
    operations.event(
        "llm_report.completed",
        scan_root=report.root,
        provider=provider,
        warnings=len(llm_warns),
        output=out_path,
        report_tree=tree_path,
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for `secanalyzer` console script and tests."""
    if argv is None:
        argv = sys.argv[1:]
    operations.configure_logging()
    parser = build_parser()
    try:
        args = parser.parse_args(list(argv))
    except SystemExit as e:
        if isinstance(e.code, int) and e.code != 0:
            return e.code
        raise

    active = _mutating_actions(args)
    action = active[0] if active else "help"
    operations.event("cli.command_started", action=action, argv=list(argv))

    try:
        if args.google_model:
            from secanalyzer import llm as llm_mod

            llm_mod.set_google_model_override(args.google_model)

        if args.output and args.scan is None and args.llm_report is None and args.analyze_issue is None:
            raise UserFacingError(
                "--output / -o is only valid with --scan, --llm-report, or --analyze-issue.",
            )
        if args.analyze_issue is not None and args.issue_number is None:
            raise UserFacingError(
                "--analyze-issue requires --issue-number N.",
            )
        if args.issue_number is not None and args.analyze_issue is None:
            raise UserFacingError(
                "--issue-number is only valid with --analyze-issue OWNER/REPO.",
            )
        if args.report_scope is not None and not args.report_context:
            raise UserFacingError(
                "--report-scope requires --report-context DIR.",
            )

        if len(active) > 1:
            raise UserFacingError(
                "Use only one primary action at a time "
                f"(got: {', '.join(active)}). Run secanalyzer --help for examples.",
            )

        if args.set_token is not None:
            exit_code = _run_set_token(args.set_token, args.provider)
        elif args.set_google_model is not None:
            exit_code = _run_set_google_model(args.set_google_model)
        elif args.api_key_status:
            exit_code = _run_api_key_status()
        elif args.test_llm:
            exit_code = _run_test_llm()
        elif args.list_google_models:
            exit_code = _run_list_google_models()
        elif args.scan is not None:
            exit_code = _run_scan(args.scan, args.output)
        elif args.llm_report is not None:
            exit_code = _run_llm_report(
                args.llm_report,
                args.output,
                report_dir=args.report_dir,
            )
        elif args.list_issues is not None:
            from secanalyzer.issues_session import run_list_issues

            exit_code = run_list_issues(args.list_issues)
        elif args.analyze_issue is not None:
            from secanalyzer.issues_session import run_analyze_issue
            from secanalyzer import output as outmod

            md, issue_warns = run_analyze_issue(
                args.analyze_issue,
                args.issue_number,
                provider_override=args.provider,
                report_tree_dir=args.report_context,
                report_scope=args.report_scope,
            )
            for w in issue_warns:
                sys.stderr.write(f"[WARNING] {w}\n")
            out_path = Path(args.output).expanduser() if args.output else None
            try:
                outmod.write_report(md, out_path)
            except OSError as e:
                raise UserFacingError(f"Could not write output: {e}") from e
            exit_code = 0
        elif args.provider is not None:
            raise UserFacingError(
                "`--provider` is only used with `--set-token llm` or `--analyze-issue` "
                "(it must match the vendor of your stored LLM key).",
            )
        else:
            parser.print_help()
            exit_code = 0
        operations.event("cli.command_completed", action=action, exit_code=exit_code)
        return exit_code
    except UserFacingError as e:
        operations.event("cli.command_failed", action=action, error=str(e), level=40)
        sys.stderr.write(f"[ERROR] {e}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
