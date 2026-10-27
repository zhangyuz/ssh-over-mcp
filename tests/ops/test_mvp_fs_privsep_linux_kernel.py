"""Actual sudo -> setpriv kernel admission proof on disposable hosted Ubuntu.

Uses the exact fixed candidate argv except its final Python payload is a
read-only /proc status probe. NOT an OCI SSH login or release acceptance.
Never executes sudo from a developer or self-hosted runner.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SUDOERS = ROOT / "deploy/ssh-target/sudoers.fs-privsep-review-candidate"
SSHD = ROOT / "deploy/ssh-target/sshd_config.fs-privsep-review-candidate"
PREFIX = "ssh-over-mcp-e2e-host ALL=(root) NOPASSWD: "
STATUS_PROBE = """
import json
import os
from pathlib import Path

fields = {}
for raw in Path('/proc/self/status').read_text().splitlines():
    k, _, v = raw.partition(':')
    if k in ('Uid', 'Gid', 'Groups', 'NoNewPrivs',
             'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'):
        fields[k] = v.strip().split()
fields['resuid'] = list(os.getresuid())
fields['resgid'] = list(os.getresgid())
fields['groups'] = os.getgroups()
try:
    with open('/etc/shadow', 'rb'):
        fields['shadow_denied'] = False
except PermissionError:
    fields['shadow_denied'] = True
print(json.dumps(fields))
"""


def _fixed_setpriv_args() -> list[str]:
    conf = SSHD.read_text()
    forced = [x for x in conf.splitlines() if x.startswith("ForceCommand ")]
    assert len(forced) == 1
    rules = [x for x in SUDOERS.read_text().splitlines() if x.startswith(PREFIX)]
    assert len(rules) == 1
    exact = shlex.split(rules[0][len(PREFIX) :])
    assert shlex.split(forced[0][len("ForceCommand ") :]) == [
        "/usr/bin/sudo",
        "-n",
        *exact,
    ]
    assert exact[:1] == ["/usr/bin/setpriv"]
    assert exact[-4:] == [
        "/usr/bin/python3",
        "-I",
        "-S",
        "/usr/local/libexec/ssh-over-mcp-fs-only-launcher.py",
    ]
    return exact


def test_fixed_sudo_setpriv_arguments_are_kernel_testable():
    args = _fixed_setpriv_args()
    for fixed in (
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
        "--no-new-privs",
        "--reuid=2201",
        "--regid=3201",
        "--clear-groups",
    ):
        assert fixed in args
    assert not any(x.startswith("-c") for x in args)


@pytest.mark.skipif(sys.platform != "linux", reason="requires actual Linux kernel")
def test_hosted_ephemeral_sudo_setpriv_drops_all_caps_before_python():
    # sudo on untrusted code is NEVER run on a persistent user/CI machine.
    if os.environ.get("GITHUB_ACTIONS") != "true":
        pytest.skip("privileged probe permitted only on disposable GitHub-hosted Ubuntu")
    # On CI, never silently skip a proof or run sudo on a self-hosted host.
    assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    assert os.environ.get("RUNNER_OS") == "Linux"
    assert Path("/usr/bin/sudo").is_file()
    assert Path("/usr/bin/setpriv").is_file()
    assert Path("/usr/bin/python3").is_file()

    fixed = _fixed_setpriv_args()
    # Replace ONLY the final immutable launcher path with an innocuous
    # read-only /proc script for this kernel transition probe.
    probe = [
        "/usr/bin/sudo",
        "-n",
        *fixed[:-1],
        "-c",
        STATUS_PROBE,
    ]
    result = subprocess.run(probe, capture_output=True, text=True, timeout=15, check=False)
    assert result.returncode == 0, result.stderr[-600:]
    state = json.loads(result.stdout)
    assert state["resuid"] == [2201, 2201, 2201]
    assert state["resgid"] == [3201, 3201, 3201]
    assert state["Uid"] == ["2201"] * 4
    assert state["Gid"] == ["3201"] * 4
    assert state["groups"] == []
    assert state["Groups"] == []
    assert state["NoNewPrivs"] == ["1"]
    for cap in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        assert int(state[cap][0], 16) == 0, (cap, state[cap])
    assert state["shadow_denied"] is True
