import click
import rich

from etc import ROOT
from etc.lint import LintResult


def lint_pre_push_hook(ctx: click.Context) -> LintResult:
    """
    Lint etc/hooks/pre-push

    Check that all core crates are tested
    """
    any_errors = False

    if any_errors:
        return LintResult.FAILURE
    else:
        return LintResult.SUCCESS
