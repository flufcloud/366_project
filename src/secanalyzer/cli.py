"""CLI entry point: parse arguments, route subcommands, and surface errors without raw tracebacks."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path
from typing import Sequence

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
        help="Scan a local repository and generate security documentation (Markdown).",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="With --scan, write Markdown to FILE instead of stdout.",
    )
    parser.add_argument(
        "--issues",
        metavar="OWNER/REPO",
        help="Fetch open issues and PRs from GitHub and launch the interactive analyzer.",
    )
    parser.add_argument(
        "--api-key-status",
        action="store_true",
        help="Check whether configured API keys are present and valid.",
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
        help="With --set-token llm, choose vendor (claude, gemini, anthropic). With --issues, must match stored LLM vendor.",
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
    if args.scan is not None:
        names.append("--scan")
    if args.issues is not None:
        names.append("--issues")
    return names


def _run_set_token(kind: str, provider: str | None) -> int:
    from secanalyzer import config
    from secanalyzer.exceptions import ConfigurationError

    if kind == "github":
        token = getpass.getpass("GitHub token (input hidden): ")
        try:
            config.save_github_token(token)
        except ConfigurationError as e:
            raise UserFacingError(str(e)) from e
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
    sys.stderr.write("LLM credentials saved under secanalyzer config directory.\n")
    return 0


def _run_api_key_status() -> int:
    from secanalyzer import config
    from secanalyzer.exceptions import ConfigurationError

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

    return 0 if healthy else 1


def _run_scan(scan_path: str, output: str | None) -> int:
    from secanalyzer import output as outmod
    from secanalyzer import repo_analyzer
    from secanalyzer.exceptions import ScanError

    out_path = Path(output).expanduser() if output else None
    try:
        report = repo_analyzer.scan_repository(scan_path)
    except ScanError as e:
        raise UserFacingError(str(e)) from e

    if report.total_redactions > 0:
        sys.stderr.write(
            "[WARNING] Content redacted before reporting: "
            f"{report.total_redactions} pattern match(es) in scanned files.\n",
        )
    md = repo_analyzer.report_to_markdown(report)
    try:
        outmod.write_report(md, out_path)
    except OSError as e:
        raise UserFacingError(f"Could not write output: {e}") from e
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for `secanalyzer` console script and tests."""
    if argv is None:
        argv = sys.argv[1:]
    parser = build_parser()
    try:
        args = parser.parse_args(list(argv))
    except SystemExit as e:
        if isinstance(e.code, int) and e.code != 0:
            return e.code
        raise

    try:
        if args.output and args.scan is None:
            raise UserFacingError("--output / -o is only valid together with --scan PATH.")

        active = _mutating_actions(args)
        if len(active) > 1:
            raise UserFacingError(
                "Use only one primary action at a time "
                f"(got: {', '.join(active)}). Run secanalyzer --help for examples.",
            )

        if args.set_token is not None:
            return _run_set_token(args.set_token, args.provider)

        if args.api_key_status:
            return _run_api_key_status()

        if args.scan is not None:
            return _run_scan(args.scan, args.output)

        if args.issues is not None:
            from secanalyzer.issues_session import run_interactive_issues

            return run_interactive_issues(
                args.issues,
                provider_override=args.provider,
            )

        if args.provider is not None:
            raise UserFacingError(
                "`--provider` is only used with `--set-token llm` or `--issues` "
                "(it must match the vendor of your stored LLM key).",
            )

        parser.print_help()
        return 0
    except UserFacingError as e:
        sys.stderr.write(f"[ERROR] {e}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
