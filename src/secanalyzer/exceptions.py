"""User-facing errors (no raw tracebacks in CLI output)."""


class UserFacingError(Exception):
    """Raised for expected failures; ``str(e)`` is safe to print to stderr."""


class ConfigurationError(UserFacingError):
    """Invalid or missing configuration."""


class ScanError(UserFacingError):
    """Repository scan or path validation failure."""


class GitHubApiError(UserFacingError):
    """GitHub REST API failure."""


class LLMError(UserFacingError):
    """LLM request assembly, safety check, or provider failure."""
