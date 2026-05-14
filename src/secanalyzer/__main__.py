"""Allow `python -m secanalyzer` (see README troubleshooting)."""

from secanalyzer.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
