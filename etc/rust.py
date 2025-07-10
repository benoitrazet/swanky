from enum import Enum
from pathlib import Path

from etc import ROOT


class CrateDir(Enum):
    EDGE = "edge"
    CORE = "core"


def crate_path(name: str, crate_dir: CrateDir) -> Path:
    """
    Given a crate named `name`, where should it live?

    For example:
    swanky-cool-crate: ./edge/cool-crate, ./edge/cool/crate (both valid)

    If ./edge/cool exists (and isn't a crate), then we _require_ that cool-crate live under
    that directory.

    This function will raise a `ValueError` if `name` doesn't start with `swanky-`

    `crate_dir` determines which directory (edge or core) the crate lives in
    """
    parts = name.split("-")
    if len(parts) == 0 or parts[0] != "swanky":
        raise ValueError(f"Invalid crate name {repr(name)}")
    del parts[0]
    dir = ROOT / crate_dir.value
    for i, part in enumerate(parts):
        dir_part = dir / part
        if dir_part.is_dir() and (not (dir_part / "Cargo.toml").exists()):
            dir = dir_part
        else:
            break
    suffix = "-".join(parts[i:])
    return dir / suffix
