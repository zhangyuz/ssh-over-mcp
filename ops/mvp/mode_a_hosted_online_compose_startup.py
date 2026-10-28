"""GitHub-hosted disposable full Compose startup, never a production release.

All keys, data and Compose resources are synthetic and unique. The ephemeral
overlay removes STOP78 *only* in /tmp and only on a GitHub-hosted PR runner.
This tests whether the actual Compose services can boot, not public ingress,
independent operator authorization, production keys or final image signatures.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from mode_a_hosted_oci_fs_smoke import prepare, run

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "som342-control-ci:local"
NODE = "som-mvp-fs-online-pilot-review:local"
SUBNET = "172.30.253.0/24"
ORIGIN = "172.30.253.10"
COMPOSE = ROOT / "deploy" / "compose"

# Control images and node SSH images are already CI-buildable and tests need
# no release-time registry, network-exposed ports or production credentials.
OVERLAY = """services:
  node01:
    entrypoint: !reset null
    command: !reset null
  node02:
    entrypoint: !reset null
    command: !reset null
"""


def cli(args: list[str], *, env: dict[str, str] | None = None, timeout: int = 85):
    result = subprocess.run(
        args, env=env, text=True, capture_output=True, timeout=timeout, check=False
    )
    if result.returncode:
        # Never print stdout, Compose config, token or host paths.
        raise AssertionError((args[:2], result.returncode, result.stderr[-350:]))
    return result.stdout


def write_secret(path: Path, data: bytes, *, uid: int = 10001, gid: int = 10003):
    path.write_bytes(data)
    path.chmod(0o400)
    run(["sudo", "-n", "chown", f"{uid}:{gid}", str(path)])


def payload(work: Path) -> dict[str, str]:
    nodes = []
    for i in (1, 2):
        current = work / f"node{i:02}"
        host, client, _ = prepare(current, f"node{i:02}")
        nodes.append((current, host, client))
    root = work / "operator"
    root.mkdir(mode=0o755)
    private = root / "ssh-secrets"
    private.mkdir(mode=0o700)
    hosts: dict[str, dict] = {}
    credentials: dict[str, str] = {}
    for i, (_, host, client) in enumerate(nodes, 1):
        alias = f"node{i:02}"
        pub = host.with_suffix(".pub").read_text().split()
        assert len(pub) >= 2 and pub[0] == "ssh-ed25519"
        hosts[alias] = {
            "address": alias,
            "port": 2222,
            "ssh_user": "ssh-over-mcp-e2e-host",
            "credential_ref": f"client{i}",
            "host_key": " ".join(pub[:2]),
            "allowed_roles": ["rw-operator"],
        }
        write_secret(private / f"client{i}", client.read_bytes())
        credentials[f"client{i}"] = f"/run/secrets/ssh/client{i}"
    private.chmod(0o500)
    run(["sudo", "-n", "chown", "10001:10003", str(private)])
    paths = [f"/srv/data/mvp-node-{i}" for i in (1, 2)]
    policy = {
        "inventory": {"hosts": hosts},
        "policy": {
            "version": 1,
            "default": "deny",
            "roles": {"rw-operator": {}},
            "risk": {"approval_required": ["medium", "high", "critical"]},
            "rules": [
                {
                    "id": "oci.two-node.fs-only",
                    "effect": "allow",
                    "roles": ["rw-operator"],
                    "hosts": ["node01", "node02"],
                    "tools": ["fs_stat", "fs_read", "fs_mkdir", "fs_write"],
                    "paths": [*paths, *(f"{p}/approved.bin" for p in paths)],
                }
            ],
        },
    }
    cfg = root / "config.yaml"
    creds = root / "credentials.yaml"
    bearer = root / "origin-bearer"
    write_secret(cfg, json.dumps(policy).encode())
    write_secret(creds, json.dumps({"credentials": credentials}).encode())
    write_secret(bearer, secrets.token_urlsafe(32).encode())
    env = {
        "PATH": os.environ["PATH"],
        "HOME": os.environ["HOME"],
        "COMPOSE_DISABLE_ENV_FILE": "1",
        "SSH_OVER_MCP_IMAGE": IMAGE,
        "SSH_OVER_MCP_NODE01_IMAGE": NODE,
        "SSH_OVER_MCP_NODE02_IMAGE": NODE,
        "SSH_OVER_MCP_PROFILE": "rw-operator",
        "SSH_OVER_MCP_MODE_A_ORIGIN_IPV4": ORIGIN,
        "SSH_OVER_MCP_MODE_A_ORIGIN_CIDR": SUBNET,
        "SSH_OVER_MCP_CONFIG_FILE": str(cfg),
        "SSH_OVER_MCP_CREDENTIAL_MAP_FILE": str(creds),
        "SSH_OVER_MCP_SSH_SECRETS_DIR": str(private),
        "SSH_OVER_MCP_ORIGIN_BEARER_FILE": str(bearer),
        "SSH_OVER_MCP_NODE01_HOSTKEYS_DIR": str(nodes[0][0] / "hostkeys"),
        "SSH_OVER_MCP_NODE02_HOSTKEYS_DIR": str(nodes[1][0] / "hostkeys"),
        "SSH_OVER_MCP_NODE01_AUTHORIZED_KEYS_DIR": str(nodes[0][0] / "authorized_keys"),
        "SSH_OVER_MCP_NODE02_AUTHORIZED_KEYS_DIR": str(nodes[1][0] / "authorized_keys"),
    }
    return env


def main() -> None:
    assert sys.platform == "linux" and os.geteuid() != 0
    assert os.getenv("GITHUB_ACTIONS") == "true"
    assert os.getenv("RUNNER_ENVIRONMENT") == "github-hosted"
    assert os.getenv("GITHUB_EVENT_NAME") == "pull_request"
    assert os.getenv("GITHUB_EVENT_PATH") and os.getenv("RUNNER_TEMP")
    assert os.getenv("GITHUB_REPOSITORY") == "zhangyuz/ssh-over-mcp"
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    assert event["pull_request"]["number"] == 342
    assert event["pull_request"]["head"]["repo"]["full_name"] == "zhangyuz/ssh-over-mcp"
    assert shutil.which("docker") and shutil.which("ssh-keygen")
    # No production keys, no host ports, and no shared Yuz.local Engine.
    platform = cli(["docker", "info", "--format", "{{.OSType}}/{{.Architecture}}"]).strip()
    assert platform in {"linux/amd64", "linux/x86_64"}, "unexpected Docker Engine architecture"

    cli(
        ["docker", "build", "--no-cache", "-f", str(ROOT / "Dockerfile"), "-t", IMAGE, str(ROOT)],
        timeout=360,
    )
    for tag in (NODE, IMAGE):
        assert (
            cli(["docker", "image", "inspect", tag, "--format", "{{.Id}}"])
            .strip()
            .startswith("sha256:")
        )
    assert (
        cli(["docker", "image", "inspect", NODE, "--format", "{{json .Config.Entrypoint}}"]).strip()
        == '["/usr/sbin/sshd"]'
    )

    with tempfile.TemporaryDirectory(prefix="som342-compose-ci-", dir="/tmp") as tmp:
        work = Path(tmp)
        work.chmod(0o755)
        override = work / "runnable-ci-only.yaml"
        override.write_text(OVERLAY)
        project = "som342c" + uuid.uuid4().hex[:9]
        cmd = [
            "docker",
            "compose",
            "--project-name",
            project,
            "-f",
            str(COMPOSE / "compose.yaml"),
            "-f",
            str(COMPOSE / "compose.dev-ssh.yaml"),
            "-f",
            str(COMPOSE / "compose.mode-a-openssh-fs.review-candidate.yaml"),
            "-f",
            str(override),
            "--profile",
            "mvp-fs-review",
        ]
        env: dict[str, str] | None = None
        try:
            env = payload(work)
            # Hide Docker credential stores from the generated test operator.
            docker_meta = work / "docker-config"
            docker_meta.mkdir(mode=0o700)
            env["DOCKER_CONFIG"] = str(docker_meta)
            rendered = json.loads(cli(cmd + ["config", "--format", "json"], env=env))
            for node in ("node01", "node02"):
                service = rendered["services"][node]
                # Entry-point removal must fall back to the *image* default.
                assert service.get("entrypoint") in (None, [])
                assert service.get("command") in (None, [])
                assert service["image"] == NODE and not service.get("ports")
            assert rendered["services"]["mcp"]["environment"]["SSH_OVER_MCP_BIND_HOST"] == ORIGIN
            assert not rendered["services"]["mcp"].get("ports")
            assert all(
                rendered["networks"][n]["internal"]
                for n in ("origin_internal", "node01_ssh", "node02_ssh")
            )
            # Ledger-init is an explicit dependency; no Cloudflare/admin
            # tunnel is created. Exactly these five roles must work.
            cli(
                cmd
                + [
                    "up",
                    "-d",
                    "--no-build",
                    "--wait",
                    "ledger-init",
                    "ledger",
                    "mcp",
                    "node01",
                    "node02",
                ],
                env=env,
                timeout=210,
            )
            raw = cli(cmd + ["ps", "--all", "--format", "json"], env=env)
            rows = (
                json.loads(raw)
                if raw.strip().startswith("[")
                else [json.loads(line) for line in raw.splitlines() if line.strip()]
            )
            services = {r["Service"]: r for r in rows}
            assert set(services) == {"ledger-init", "ledger", "mcp", "node01", "node02"}
            assert services["ledger-init"]["ExitCode"] == 0
            for role in ("ledger", "mcp", "node01", "node02"):
                assert services[role]["State"] == "running", (role, services[role]["State"])
            assert services["mcp"].get("Health") == "healthy"
            for node in ("node01", "node02"):
                cli(cmd + ["exec", "-T", node, "/usr/sbin/sshd", "-t"], env=env)
            # Check the *actual* control application can talk to Ledger and
            # its MCP socket. Healthcheck already used origin-only HTTP readyz.
            cli(
                cmd
                + [
                    "exec",
                    "-T",
                    "mcp",
                    "python",
                    "-c",
                    (
                        "import os,urllib.request; "
                        "addr=os.environ['SSH_OVER_MCP_BIND_HOST']; "
                        "assert urllib.request.urlopen('http://'+addr+':8000/readyz',timeout=3).status==200"
                    ),
                ],
                env=env,
            )
            print("MODE_A_COMPOSE_ALL_FIVE_SERVICES_HEALTHY_CI_ONLY_PASS", flush=True)
            print(
                "TEST_ONLY=no-production-keys RELEASE_AUTHORIZED=false DEPLOYED=false", flush=True
            )
        finally:
            # The only Compose resource scope eligible for teardown is this
            # unguessable disposable project. No global Docker prune.
            if env is not None:
                result = subprocess.run(
                    cmd + ["down", "--volumes", "--remove-orphans"],
                    env=env,
                    capture_output=True,
                    timeout=85,
                    check=False,
                )
                if result.returncode:
                    print("MODE_A_COMPOSE_EPHEMERAL_TEARDOWN_FAILED", file=sys.stderr)
            # Synthetic host key fixtures can have container-root ownership.
            for node in ("node01", "node02"):
                for target in ("hostkeys", "authorized_keys"):
                    path = work / node / target
                    if path.is_dir() and not path.is_symlink():
                        run(["sudo", "-n", "rm", "-rf", "--", str(path)], ok=False)
            secret_dir = work / "operator"
            if secret_dir.exists() and not secret_dir.is_symlink():
                run(["sudo", "-n", "rm", "-rf", "--", str(secret_dir)], ok=False)


if __name__ == "__main__":
    main()
