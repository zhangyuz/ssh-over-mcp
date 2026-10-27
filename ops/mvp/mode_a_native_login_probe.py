"""Bounded, disposable feasibility probe for OpenSSH native-login FS admission.

Creates one SECOND, loopback-only sshd in an existing temporary hosted OCI
node. Tests fixed ForceCommand with NO sudo or new capabilities. It does not
alter the signed image, primary sshd config, production STOP78, or host keys.
An unsuccessful probe is an explicit REJECTION of this candidate, not a pass.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path


def run(args: list[str], *, data: bytes | None = None, timeout: int = 12):
    return subprocess.run(args, input=data, capture_output=True, timeout=timeout, check=False)


PROBE = rb"""import json,os,sys
fields={}
with open('/proc/self/status',encoding='ascii') as f:
 for line in f:
  if ':' in line:
   k,v=line.split(':',1)
   if k in ('NoNewPrivs','CapInh','CapPrm','CapEff','CapBnd','CapAmb'):
    fields[k]=v.strip()
try:
 with open('/etc/ssh/hostkeys/ssh_host_ed25519_key','rb') as k:
  k.read(1)
 hostkey_denied=False
except PermissionError:
 hostkey_denied=True
uid_ok=os.getresuid()==(2201,2201,2201)
gid_ok=os.getresgid()==(3201,3201,3201)
nonbounding_zero=all(fields.get(k)=='0000000000000000' for k in ('CapInh','CapPrm','CapEff','CapAmb'))
bounding_hex=fields.get('CapBnd','')
bounding_zero=bounding_hex=='0000000000000000'
# Exact four admission capabilities: SETGID=6, SETUID=7,
# SETPCAP=8, SYS_CHROOT=18. Never accept a broader inherited mask.
admission_mask=(1<<6)|(1<<7)|(1<<8)|(1<<18)
try:
 bounding_limited=int(bounding_hex,16)==admission_mask
except ValueError:
 bounding_limited=False
def denied(action):
 try:
  action()
 except PermissionError:
  return True
 return False
root_uid_denied=denied(lambda:os.setresuid(0,0,0))
root_gid_denied=denied(lambda:os.setresgid(0,0,0))
chroot_denied=denied(lambda:os.chroot('/tmp'))
setgroups_denied=denied(lambda:os.setgroups([]))
zero=nonbounding_zero and bounding_zero
nnp=fields.get('NoNewPrivs')=='1'
status={'uid_ok':uid_ok,'gid_ok':gid_ok,'caps_zero':zero,'nnp':nnp,'hostkey_denied':hostkey_denied,'four_sets_zero':nonbounding_zero,'bounding_zero':bounding_zero,'bounding_limited':bounding_limited,'root_uid_denied':root_uid_denied,'root_gid_denied':root_gid_denied,'chroot_denied':chroot_denied,'setgroups_denied':setgroups_denied}
print(json.dumps(status,sort_keys=True),flush=True)
sys.exit(0 if all(status.values()) else 77)
"""

# A previous strict probe proved unprivileged native login cannot use
# --bounding-set=-all (EPERM; no CAP_SETPCAP). Instead measure what *native*
# OpenSSH login + unprivileged NNP actually supplies. Keep demanding the
# original all-five-sets-zero release contract: if bounding is not zero,
# this proposal is NOT ACCEPTED; do not weaken the invariant to get green.
FORCE = (
    "ForceCommand /usr/bin/setpriv --no-new-privs "
    "/usr/bin/python3 -I -S /tmp/som342-native-probe.py"
)


def check(name: str, known: Path) -> bool:
    assert os.getenv("GITHUB_ACTIONS") == "true"
    assert os.getenv("RUNNER_ENVIRONMENT") == "github-hosted"
    assert os.getenv("GITHUB_EVENT_NAME") == "pull_request"
    assert os.name == "posix" and os.getuid() != 0
    initial = run(["docker", "exec", "-u", "0:0", name, "cat", "/etc/ssh/sshd_config"])
    assert initial.returncode == 0
    original = initial.stdout.decode()
    assert original.count("Port 2222\n") == 1
    assert original.count("ForceCommand ") == 1
    candidate = original.replace("Port 2222\n", "Port 2223\nListenAddress 127.0.0.1\n")
    candidate = (
        "\n".join(
            FORCE if line.startswith("ForceCommand ") else line for line in candidate.splitlines()
        )
        + "\n"
    )
    assert "sudo" not in FORCE and "CAP_AUDIT_WRITE" not in candidate
    for dest, payload in (
        ("/tmp/som342-native-sshd.cfg", candidate.encode()),
        ("/tmp/som342-native-probe.py", PROBE),
        (
            "/tmp/som342-native-known_hosts",
            known.read_bytes().replace(b"[127.0.0.1]:2222", b"[127.0.0.1]:2223"),
        ),
    ):
        assert (
            run(
                [
                    "docker",
                    "exec",
                    "-i",
                    "-u",
                    "0:0",
                    name,
                    "/bin/sh",
                    "-c",
                    f"umask 077; cat > {dest}; chmod 0644 {dest}",
                ],
                data=payload,
            ).returncode
            == 0
        )
    validity = run(
        [
            "docker",
            "exec",
            "-u",
            "0:0",
            name,
            "/usr/sbin/sshd",
            "-t",
            "-f",
            "/tmp/som342-native-sshd.cfg",
        ]
    )
    assert validity.returncode == 0, validity.stderr[-450:]
    started = run(
        [
            "docker",
            "exec",
            "-d",
            "-u",
            "0:0",
            name,
            "/usr/sbin/sshd",
            "-D",
            "-e",
            "-f",
            "/tmp/som342-native-sshd.cfg",
        ]
    )
    assert started.returncode == 0, started.stderr[-450:]
    for _ in range(40):
        probe = run(
            [
                "docker",
                "exec",
                "-u",
                "0:0",
                name,
                "/usr/bin/python3",
                "-c",
                "import socket; s=socket.create_connection(('127.0.0.1',2223),1); s.close()",
            ],
            timeout=4,
        )
        if probe.returncode == 0:
            break
        time.sleep(0.1)
    else:
        raise AssertionError("native login probe's second sshd did not listen")
    result = run(
        [
            "docker",
            "exec",
            "-i",
            "-u",
            "0:0",
            name,
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
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "UserKnownHostsFile=/tmp/som342-native-known_hosts",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-i",
            "/tmp/client",
            "-p",
            "2223",
            "ssh-over-mcp-e2e-host@127.0.0.1",
            "mcp-v1",
        ],
        timeout=18,
    )
    status = None
    if result.stdout:
        try:
            status = json.loads(result.stdout)
        except (UnicodeError, ValueError):
            pass
    if isinstance(status, dict):
        # Diagnostic summary uses only boolean kernel/protection assertions;
        # no SSH keys, request data, or arbitrary stdout is published.
        print(
            "NATIVE_OPENSSH_NO_SUDO_KERNEL_CHECKS="
            + json.dumps(
                {
                    key: status.get(key) is True
                    for key in (
                        "uid_ok",
                        "gid_ok",
                        "caps_zero",
                        "nnp",
                        "hostkey_denied",
                        "four_sets_zero",
                        "bounding_zero",
                        "bounding_limited",
                        "root_uid_denied",
                        "root_gid_denied",
                        "chroot_denied",
                        "setgroups_denied",
                    )
                },
                sort_keys=True,
            ),
            flush=True,
        )
        # This branch can only be claimed safe with all checks explicitly
        # true; no source line or private SSH key bytes are ever emitted.
        assert status.get("hostkey_denied") is True, "SSH login read root hostkey"
        verified = all(
            status.get(k) is True
            for k in ("uid_ok", "gid_ok", "caps_zero", "nnp", "hostkey_denied")
        )
        # Diagnostic candidate is NOT the five-zero production release gate.
        candidate = all(
            status.get(k) is True
            for k in (
                "uid_ok",
                "gid_ok",
                "four_sets_zero",
                "nnp",
                "hostkey_denied",
                "bounding_limited",
                "root_uid_denied",
                "root_gid_denied",
                "chroot_denied",
                "setgroups_denied",
            )
        )
        if candidate:
            print("NATIVE_OPENSSH_NO_SUDO_LIMITED_BOUNDING_NEGATIVES_PASS_ONLY", flush=True)
        assert verified == (result.returncode == 0)
        if verified:
            print("NATIVE_OPENSSH_NO_SUDO_FULL_KERNEL_BOUNDARY_PASS", flush=True)
            return True
    print("NATIVE_OPENSSH_NO_SUDO_FULL_KERNEL_BOUNDARY_NOT_PROVEN", flush=True)
    # This stderr is emitted only by the synthetic no-sudo ForceCommand.
    # It is bounded and never includes private-key content or stdin frames.
    diagnostic = result.stderr.decode("utf-8", errors="replace")[:160]
    print("NATIVE_OPENSSH_NO_SUDO_STDERR=" + repr(diagnostic), flush=True)
    print(
        "NATIVE_OPENSSH_NO_SUDO_EXIT="
        + str(result.returncode)
        + " OUTPUT_LENGTHS="
        + str((len(result.stdout), len(result.stderr))),
        flush=True,
    )
    return False
