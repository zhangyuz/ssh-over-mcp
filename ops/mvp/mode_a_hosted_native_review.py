"""CI-ONLY native OpenSSH FS launcher admission candidate, never production.

Stages two root-owned immutable read-only bind mounts from reviewed in-repo
source into disposable hosted OCI nodes, preserving image STOP78 and policy.
The sole changed gate is CapBnd exact four admission bits instead of zero;
all nonbounding caps must remain zero and NNP must be one. This is a test
of functional compatibility, NOT a security signoff or release promotion.
"""

from __future__ import annotations

import os
from pathlib import Path

from mode_a_hosted_oci_fs_smoke import run

BASE = Path(__file__).resolve().parents[2]
CI_LAUNCHER = "/usr/local/libexec/ssh-over-mcp-fs-only-native-review.py"
CI_CONFIG = "/etc/ssh/sshd_config"
FOUR_CAPS = (1 << 6) | (1 << 7) | (1 << 8) | (1 << 18)


def stage(directory: Path) -> list[str]:
    assert os.getenv("GITHUB_ACTIONS") == "true"
    assert os.getenv("RUNNER_ENVIRONMENT") == "github-hosted"
    assert os.getenv("GITHUB_EVENT_NAME") == "pull_request"
    launcher_src = (BASE / "ops/mvp/ssh-over-mcp-fs-only-launcher.py").read_text()
    old_gate = (
        'or any(found[name] != zero for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))'
    )
    new_gate = (
        'or any(found[name] != zero for name in ("CapInh", "CapPrm", "CapEff", "CapAmb"))'
        '\n        or int(found["CapBnd"], 16) != 0x401c0'
        '\n        or found.get("Seccomp") != "2"'
    )
    # CapBnd mask is computed separately, never assume the hardcoded
    # literal matches expected bits or accept a broader root capability set.
    assert FOUR_CAPS == 0x401C0
    assert launcher_src.count(old_gate) == 1
    assert "setpriv" not in launcher_src
    code = launcher_src.replace(old_gate, new_gate)
    assert code != launcher_src and code.count(new_gate) == 1
    old_fields = '"CapBnd", "CapAmb"}'
    new_fields = '"CapBnd", "CapAmb", "Seccomp"}'
    assert code.count(old_fields) == 1
    code = code.replace(old_fields, new_fields)
    assert code.count(new_fields) == 1
    config_src = (BASE / "deploy/ssh-target/sshd_config.fs-privsep-review-candidate").read_text()
    sudo_force = next(line for line in config_src.splitlines() if line.startswith("ForceCommand "))
    assert config_src.count("ForceCommand ") == 1
    assert "/usr/bin/sudo -n /usr/bin/setpriv" in sudo_force
    native_force = (
        "ForceCommand /usr/bin/setpriv --no-new-privs /usr/bin/python3 -I -S " + CI_LAUNCHER
    )
    cfg = config_src.replace(sudo_force, native_force)
    assert "ForceCommand /usr/bin/sudo" not in cfg and "ForceCommand " in cfg
    assert "PermitRootLogin no" in cfg and "DisableForwarding yes" in cfg
    staging = [
        ("fs-only-native-review.py", code, CI_LAUNCHER, "0555"),
        ("sshd_config.native-review", cfg, CI_CONFIG, "0644"),
    ]
    mapped_root = os.getenv("SOM342_REMAPPED_ROOT_UID")
    mapped_gid = os.getenv("SOM342_REMAPPED_ROOT_GID")
    owner = f"{int(mapped_root)}:{int(mapped_gid)}" if mapped_root and mapped_gid else "0:0"
    if mapped_root:
        assert int(mapped_root) >= 65536 and int(mapped_gid) >= 65536
    mounts = []
    for filename, contents, dest, mode in staging:
        src = directory / filename
        src.write_text(contents)
        run(["sudo", "-n", "chown", owner, str(src)])
        run(["sudo", "-n", "chmod", mode, str(src)])
        mounts.extend(["--mount", f"type=bind,src={src},dst={dest},readonly"])
    return mounts
