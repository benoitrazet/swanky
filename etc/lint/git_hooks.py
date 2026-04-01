import tomllib

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

    # Get actual / expected core crates from root manifest
    cargo_toml_path = ROOT / "Cargo.toml"
    cargo_toml = cargo_toml_path.read_text()

    try:
        manifest = tomllib.loads(cargo_toml)
    except tomllib.TOMLDecodeError:
        rich.print(f"{ROOT}/Cargo.toml is malformed.")
        return LintResult.FAILURE

    actual_core_crates = {
        crate
        for crate, params in manifest["workspace"]["dependencies"].items()
        if "path" in params and "core" in params["path"]
    }

    if any_errors:
        return LintResult.FAILURE
    else:
        return LintResult.SUCCESS
