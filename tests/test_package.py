"""Tests for package metadata and import surface."""


def test_version_exported():
    from secanalyzer import __version__

    assert __version__ == "0.1.0"


def test_stub_modules_importable():
    import secanalyzer.config
    import secanalyzer.github_client
    import secanalyzer.issues_session
    import secanalyzer.llm
    import secanalyzer.output
    import secanalyzer.repo_analyzer

    for mod in (
        secanalyzer.config,
        secanalyzer.github_client,
        secanalyzer.issues_session,
        secanalyzer.llm,
        secanalyzer.output,
        secanalyzer.repo_analyzer,
    ):
        assert mod.__doc__ is not None
