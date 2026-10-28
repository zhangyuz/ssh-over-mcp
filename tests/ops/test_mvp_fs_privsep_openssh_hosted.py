"""Real OpenSSH root host-key custody -> fixed sudo/setpriv -> zero-cap FS identity.

One disposable GitHub-hosted Ubuntu CI runner only. No production SSH ports,
persistent hosts, Docker, local Lima, or real model-controlled operations.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SSH_TEMPLATE = ROOT / "deploy/ssh-target/sshd_config.fs-privsep-review-candidate"
SUDOERS_TEMPLATE = ROOT / "deploy/ssh-target/sudoers.fs-privsep-review-candidate"


def _fixed_setpriv_args() -> list[str]:
    """Require SSH ForceCommand to match the one permitted sudoers command."""
    conf_lines = SSH_TEMPLATE.read_text().splitlines()
    commands = [x for x in conf_lines if x.startswith("ForceCommand ")]
    rules = [
        x
        for x in SUDOERS_TEMPLATE.read_text().splitlines()
        if x.startswith("ssh-over-mcp-e2e-host ALL=(root) NOPASSWD: ")
    ]
    assert len(commands) == len(rules) == 1
    args = shlex.split(rules[0].split("NOPASSWD: ", 1)[1])
    assert shlex.split(commands[0].split("ForceCommand ", 1)[1]) == ["/usr/bin/sudo", "-n", *args]
    return args


def _run(*args: str, timeout: int = 10) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    assert result.returncode == 0, (args[0], result.stderr[-600:])
    return result


def _status_probe(key: str) -> str:
    # Printed result contains metadata only, never secret key contents.
    return f"""
import json
import os
from pathlib import Path
assert os.environ.get('SSH_ORIGINAL_COMMAND') == 'mcp-v1'
fields = {{}}
for row in Path('/proc/self/status').read_text().splitlines():
    k, _, v = row.partition(':')
    if k in ('Uid','Gid','Groups','NoNewPrivs','CapInh','CapPrm','CapEff','CapBnd','CapAmb'):
        fields[k] = v.strip().split()
fields['resuid'] = list(os.getresuid())
fields['resgid'] = list(os.getresgid())
try:
    with open({key!r}, 'rb'):
        fields['hostkey_denied'] = False
except PermissionError:
    fields['hostkey_denied'] = True
print(json.dumps(fields))
"""


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _ssh(user: str, port: int, client: Path, known: Path, command: str):
    return subprocess.run(
        [
            "/usr/bin/ssh",
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "CheckHostIP=no",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            f"UserKnownHostsFile={known}",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "ConnectTimeout=3",
            "-o",
            "ConnectionAttempts=1",
            "-i",
            str(client),
            "-p",
            str(port),
            f"{user}@127.0.0.1",
            command,
        ],
        capture_output=True,
        text=True,
        timeout=18,
        check=False,
    )


def test_ssh_privsep_source_is_exact_and_dormant():
    config = SSH_TEMPLATE.read_text()
    sudoers = SUDOERS_TEMPLATE.read_text()
    args = _fixed_setpriv_args()
    assert "HostKey /etc/ssh/hostkeys/ssh_host_ed25519_key" in config
    assert "StrictModes yes" in config
    assert "UsePAM no" in config
    assert "DisableForwarding yes" in config
    assert sudoers.count("NOPASSWD: ") == 1
    assert shlex.split(config.split("ForceCommand ", 1)[1].splitlines()[0]) == [
        "/usr/bin/sudo",
        "-n",
        *args,
    ]


@pytest.mark.skipif(sys.platform != "linux", reason="requires real Linux OpenSSH")
def test_hosted_root_openssh_keeps_hostkey_from_zero_cap_session():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        pytest.skip("privileged fixture only inside disposable GitHub hosted Ubuntu")
    assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    assert os.environ.get("RUNNER_OS") == "Linux"
    assert os.geteuid() != 0
    for binary in (
        "/usr/bin/sudo",
        "/usr/sbin/sshd",
        "/usr/bin/setpriv",
        "/usr/bin/ssh-keygen",
        "/usr/sbin/visudo",
        "/usr/bin/python3",
    ):
        assert Path(binary).is_file(), binary
    assert not Path("/proc/self/uid_map").is_symlink()
    username = "somfs" + uuid.uuid4().hex[:10]
    # Don't mutate an existing account: this is a genuinely ephemeral identity.
    assert not shutil.which(username)
    login_uid, login_gid = 2201, 3201
    session = uuid.uuid4().hex[:12]
    work = Path(tempfile.mkdtemp(prefix="som-openssh-root-", dir=os.environ["RUNNER_TEMP"]))
    work.chmod(0o700)
    sudoers = Path("/etc/sudoers.d") / ("zz-som-fs-" + session)
    agent = Path("/usr/local/libexec") / ("som-fs-test-" + session + ".py")
    hostkey = work / "private_host_key"
    client = work / "client"
    user_home = Path("/home") / username
    pidfile = work / "sshd.pid"
    process = None
    try:
        _run("/usr/bin/sudo", "-n", "/usr/sbin/groupadd", "-g", str(login_gid), username)
        _run(
            "/usr/bin/sudo",
            "-n",
            "/usr/sbin/useradd",
            "-u",
            str(login_uid),
            "-g",
            str(login_gid),
            "-d",
            str(user_home),
            "-M",
            "-s",
            "/bin/sh",
            username,
            timeout=25,
        )
        _run(
            "/usr/bin/sudo",
            "-n",
            "/usr/bin/install",
            "-d",
            "-o",
            username,
            "-g",
            username,
            "-m",
            "0700",
            str(user_home),
        )
        _run("/usr/bin/sudo", "-n", "/usr/sbin/usermod", "-p", "*", username)
        _run("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(hostkey))
        _run("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(client))
        _run("/usr/bin/sudo", "-n", "/usr/bin/chown", "root:root", str(hostkey))
        _run("/usr/bin/sudo", "-n", "/usr/bin/chmod", "0600", str(hostkey))
        assert (
            _run(
                "/usr/bin/sudo", "-n", "/usr/bin/stat", "-c", "%u:%g:%a", str(hostkey)
            ).stdout.strip()
            == "0:0:600"
        )
        # The authorization belongs only to the throwaway login user.
        auth = user_home / ".ssh"
        _run(
            "/usr/bin/sudo",
            "-n",
            "/usr/bin/install",
            "-d",
            "-o",
            username,
            "-g",
            username,
            "-m",
            "0700",
            str(auth),
        )
        _run(
            "/usr/bin/sudo",
            "-n",
            "/usr/bin/install",
            "-o",
            username,
            "-g",
            username,
            "-m",
            "0600",
            str(client) + ".pub",
            str(auth / "authorized_keys"),
        )
        probe_source = work / "probe.py"
        probe_source.write_text(_status_probe(str(hostkey)))
        _run("/usr/bin/sudo", "-n", "/usr/bin/install", "-d", "-m", "0755", "/usr/local/libexec")
        _run(
            "/usr/bin/sudo",
            "-n",
            "/usr/bin/install",
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "0555",
            str(probe_source),
            str(agent),
        )

        fixed = _fixed_setpriv_args()
        assert fixed[-1] == "/usr/local/libexec/ssh-over-mcp-fs-only-launcher.py"
        fixed[-1] = str(agent)
        raw_rules = SUDOERS_TEMPLATE.read_text().replace("ssh-over-mcp-e2e-host", username)
        raw_rules = raw_rules.replace(
            "/usr/local/libexec/ssh-over-mcp-fs-only-launcher.py", str(agent)
        )
        local_rules = work / "sudoers"
        local_rules.write_text(raw_rules)
        _run(
            "/usr/bin/sudo",
            "-n",
            "/usr/bin/install",
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "0440",
            str(local_rules),
            str(sudoers),
        )
        _run("/usr/bin/sudo", "-n", "/usr/sbin/visudo", "-c", "-f", str(sudoers))

        port = _free_port()
        config = SSH_TEMPLATE.read_text()
        for previous, replacement in (
            ("Port 2222", f"Port {port}\nListenAddress 127.0.0.1"),
            ("/etc/ssh/hostkeys/ssh_host_ed25519_key", str(hostkey)),
            ("/etc/ssh/authorized_keys/%u", str(auth / "authorized_keys")),
            ("ssh-over-mcp-e2e-host", username),
            ("/usr/local/libexec/ssh-over-mcp-fs-only-launcher.py", str(agent)),
        ):
            assert config.count(previous) == 1, previous
            config = config.replace(previous, replacement)
        config += f"\nPidFile {pidfile}\n"
        config_path = work / "sshd.conf"
        config_path.write_text(config)
        _run("/usr/bin/sudo", "-n", "/usr/sbin/sshd", "-t", "-f", str(config_path))
        known = work / "known_hosts"
        known.write_text(f"[127.0.0.1]:{port} {hostkey.with_suffix('.pub').read_text().strip()}\n")
        log = (work / "sshd.log").open("wb")
        try:
            process = subprocess.Popen(
                ["/usr/bin/sudo", "-n", "/usr/sbin/sshd", "-D", "-e", "-f", str(config_path)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=log,
            )
            for _ in range(50):
                if process.poll() is not None:
                    break
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.1)
            result = _ssh(username, port, client, known, "mcp-v1")
            evidence = (work / "sshd.log").read_text(errors="replace")[-2400:]
            assert result.returncode == 0, (result.stderr[-450:], evidence)
            state = json.loads(result.stdout)
            assert state["resuid"] == [login_uid] * 3
            assert state["resgid"] == [login_gid] * 3
            assert state["Uid"] == [str(login_uid)] * 4
            assert state["Gid"] == [str(login_gid)] * 4
            assert state["Groups"] == []
            assert state["NoNewPrivs"] == ["1"]
            for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
                assert int(state[name][0], 16) == 0
            assert state["hostkey_denied"] is True
            wrong_command = _ssh(username, port, client, known, "not-mcp-v1")
            assert wrong_command.returncode != 0
        finally:
            if pidfile.is_file():
                # sshd PID file may be root-owned; read only the exact ephemeral path.
                pid = int(_run("/usr/bin/sudo", "-n", "/usr/bin/cat", str(pidfile)).stdout.strip())
                if pid > 1:
                    subprocess.run(
                        ["/usr/bin/sudo", "-n", "/usr/bin/kill", "-TERM", str(pid)],
                        timeout=5,
                        check=False,
                        capture_output=True,
                    )
            if process is not None:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait(timeout=5)
            log.close()
    finally:
        # Same disposable runner, exact names that this invocation generated.
        for path in (str(sudoers), str(agent)):
            subprocess.run(
                ["/usr/bin/sudo", "-n", "/usr/bin/rm", "-f", path],
                timeout=5,
                capture_output=True,
                check=False,
            )
        subprocess.run(
            ["/usr/bin/sudo", "-n", "/usr/sbin/userdel", "-r", username],
            timeout=6,
            capture_output=True,
            check=False,
        )
        subprocess.run(
            ["/usr/bin/sudo", "-n", "/usr/sbin/groupdel", username],
            timeout=6,
            capture_output=True,
            check=False,
        )
        shutil.rmtree(work, ignore_errors=True)
