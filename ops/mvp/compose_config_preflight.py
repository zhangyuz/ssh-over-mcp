"""Offline, refusal-first checks on *rendered* Docker Compose configuration JSON.

This static operator aid is NOT a Docker/network/host trust or deployment gate.
Never run Compose, read credentials, or echo data from the supplied JSON.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from topology_preflight import Refused, _image, _read_one_regular_file

_REPORT = "som-mvp-compose-config-preflight-v1"
_CONTROL = frozenset({"ledger-init", "ledger", "mcp"})
_OPTIONAL = frozenset({"approvalctl", "cloudflared"})
_SUPPORTED_PROJECT = frozenset({"name", "services", "networks", "volumes"})
_SUPPORTED_SERVICE = frozenset(
    {
        "image",
        "entrypoint",
        "command",
        "user",
        "group_add",
        "read_only",
        "cap_drop",
        "cap_add",
        "security_opt",
        "network_mode",
        "depends_on",
        "environment",
        "healthcheck",
        "expose",
        "networks",
        "volumes",
        "profiles",
        "restart",
        "stop_grace_period",
        "init",
        "hostname",
        "working_dir",
        "logging",
        "tmpfs",
        "ulimits",
        "pids_limit",
        "mem_limit",
        "cpus",
    }
)
_TARGET_ROOT = frozenset({"node01", "node02"})
_ADMIN_VOLUMES = frozenset({"ledger-data", "ledger-exec", "ledger-admin"})

# Reviewed against deploy/compose/compose.yaml for control-plane service roles.
# These are DECLARATION checks, not runtime UID or executable provenance proof.
_ROLE_USER = {
    "ledger-init": "0:0",  # narrowly scoped bootstrap ONLY, never an SSH target
    "ledger": "10002:10002",
    "mcp": "10001:10003",
    "approvalctl": "10004:10005",
    "cloudflared": "65532:65532",
}
_ROLE_ENTRYPOINT = {
    "ledger-init": ["ssh-over-mcp-ledger-init"],
    "ledger": ["ssh-over-mcp-ledger"],
    "mcp": ["ssh-over-mcp-server"],
    "approvalctl": ["ssh-over-mcp-approvalctl"],
}
_CLOUDFLARED_COMMAND = [
    "tunnel",
    "run",
    "--token-file",
    "/run/secrets/cloudflare-tunnel-token",
]
_OPTIONAL_PROFILES = {"approvalctl": ["admin"], "cloudflared": ["cloudflare"]}

# Match the existing operator-approved local control-plane socket identity
# boundaries; name/volume checks alone cannot bind a listening endpoint.
_LEDGER_ENV = {
    "SSH_OVER_MCP_LEDGER_DB_PATH": "/var/lib/ssh-over-mcp/ledger/ledger.db",
    "SSH_OVER_MCP_LEDGER_HMAC_KEY_PATH": "/var/lib/ssh-over-mcp/ledger/ledger.key",
    "SSH_OVER_MCP_LEDGER_SERVICE_UID": "10002",
    "SSH_OVER_MCP_LEDGER_SERVICE_GID": "10002",
    "SSH_OVER_MCP_LEDGER_EXEC_SOCKET_PATH": "/run/ssh-over-mcp-exec/ledger/ledger.sock",
    "SSH_OVER_MCP_LEDGER_EXEC_SOCKET_GID": "10003",
    "SSH_OVER_MCP_LEDGER_EXEC_SOCKET_MODE": "0660",
    "SSH_OVER_MCP_LEDGER_EXEC_PEER_UID": "10001",
    "SSH_OVER_MCP_LEDGER_EXEC_PEER_GID": "10003",
    "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_PATH": "/run/ssh-over-mcp-admin/ledger/ledger.sock",
    "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_GID": "10005",
    "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_MODE": "0660",
    "SSH_OVER_MCP_LEDGER_ADMIN_PEER_UID": "10004",
    "SSH_OVER_MCP_LEDGER_ADMIN_PEER_GID": "10005",
}
_MCP_ENV = {
    "SSH_OVER_MCP_CONFIG": "/etc/ssh-over-mcp/config.yaml",
    "SSH_OVER_MCP_CREDENTIAL_MAP": "/etc/ssh-over-mcp/credentials.yaml",
    "SSH_OVER_MCP_PROFILE": "rw-operator",
    "SSH_OVER_MCP_LEDGER_EXEC_SOCKET_PATH": _LEDGER_ENV["SSH_OVER_MCP_LEDGER_EXEC_SOCKET_PATH"],
    "SSH_OVER_MCP_LEDGER_SERVICE_UID": "10002",
    "SSH_OVER_MCP_LEDGER_SERVICE_GID": "10002",
    "SSH_OVER_MCP_BIND_HOST": "0.0.0.0",
    "SSH_OVER_MCP_ORIGIN_BEARER_TOKEN_FILE": "/run/secrets/origin-bearer",
}
_APPROVAL_ENV = {
    "SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_PATH": _LEDGER_ENV["SSH_OVER_MCP_LEDGER_ADMIN_SOCKET_PATH"],
    "SSH_OVER_MCP_LEDGER_SERVICE_UID": "10002",
    "SSH_OVER_MCP_LEDGER_SERVICE_GID": "10002",
}
_ROLE_ENV = {
    "ledger-init": _LEDGER_ENV,
    "ledger": _LEDGER_ENV,
    "mcp": _MCP_ENV,
    "approvalctl": _APPROVAL_ENV,
    "cloudflared": {},
}
_MCP_READINESS_TEST = [
    "CMD",
    "python",
    "-c",
    "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/readyz',timeout=2).read()",
]


def _unsafe_rootless_storage_source(source: str) -> bool:
    """Recognize conventional rootless Engine data roots without host I/O.

    The check is lexical only. It cannot prove custom XDG_DATA_HOME, symlinks,
    mounts or the actual Docker Engine's storage location.
    """
    parts = Path(source).parts
    # Use the same normalized representation for ancestor equality and for
    # all subsequent path-component checks: /home and /home/ are equivalent.
    if parts in (("/", "home"), ("/", "root")):
        return True
    if len(parts) >= 3 and parts[1] == "home":
        # Binding a whole user home exposes ~/.local/share/docker storage.
        if len(parts) == 3:
            return True
        if len(parts) >= 4 and parts[3] == ".local":
            # .local is itself the enclosing directory of rootless storage.
            return True
    if len(parts) >= 3 and parts[1] == "root" and parts[2] == ".local":
        return True
    return any(
        parts[i : i + 3] == (".local", "share", runtime)
        for runtime in ("docker", "containers", "containerd", "podman")
        for i in range(len(parts) - 2)
    )


def _dict(value: object) -> dict:
    if type(value) is not dict:
        raise Refused("INVALID_SHAPE")
    return value


def _project(document: object) -> tuple[dict, dict, dict[str, str]]:
    root = _dict(document)
    if not set(root) <= _SUPPORTED_PROJECT:
        raise Refused("UNSUPPORTED_COMPOSE_FIELD")
    services = _dict(root.get("services"))
    networks = _dict(root.get("networks", {}))
    volumes = _dict(root.get("volumes", {}))
    if len(services) > 8 or len(networks) > 8 or len(volumes) > 16:
        raise Refused("TOO_MANY_ENTRIES")
    resolved_volumes: set[str] = set()
    volume_identities: dict[str, str] = {}
    for name, config in volumes.items():
        if type(name) is not str or type(config) is not dict:
            raise Refused("INVALID_VOLUME")
        if set(config) - {"name", "external"} or config.get("external") not in (None, False):
            raise Refused("UNSUPPORTED_VOLUME")
        resolved = config.get("name", name)
        if type(resolved) is not str or not resolved or resolved in resolved_volumes:
            raise Refused("SHARED_TARGET_VOLUME")
        resolved_volumes.add(resolved)
        volume_identities[name] = resolved
    resolved_networks: set[str] = set()
    for name, config in networks.items():
        if type(name) is not str or type(config) is not dict:
            raise Refused("INVALID_NETWORK")
        # External/custom driver networks are not an implied ACL/identity proof.
        if config.get("external") or set(config) - {"internal", "name", "driver", "ipam"}:
            raise Refused("UNSUPPORTED_NETWORK")
        # Compose 5.5 renders a harmless `ipam: {}` on ordinary bridge
        # networks. Custom subnets, gateways, options or malformed IPAM are
        # NOT in this static-only review contract.
        if "ipam" in config and (type(config["ipam"]) is not dict or config["ipam"]):
            raise Refused("UNSUPPORTED_NETWORK_IPAM")
        if config.get("driver") not in (None, "bridge"):
            raise Refused("UNSUPPORTED_NETWORK_DRIVER")
        resolved = config.get("name", name)
        if type(resolved) is not str or not resolved or resolved in resolved_networks:
            raise Refused("SHARED_NETWORK_NAME")
        resolved_networks.add(resolved)
    return services, networks, volume_identities


def _networks(service: dict, defined: dict) -> set[str]:
    value = service.get("networks", [])
    if type(value) is list:
        names = value
    elif type(value) is dict:
        names = list(value)
        if any(x is not None and type(x) is not dict for x in value.values()):
            raise Refused("INVALID_NETWORK")
    else:
        raise Refused("INVALID_NETWORK")
    if any(type(name) is not str for name in names) or len(names) != len(set(names)):
        raise Refused("INVALID_NETWORK")
    if not set(names) <= set(defined):
        raise Refused("INVALID_NETWORK")
    return set(names)


def _reviewed_runtime_configuration(role: str, config: dict) -> None:
    """Pin identity-bearing environment and refuse alternate executable routes."""
    expected_env = _ROLE_ENV.get(role, {})
    environment = config.get("environment", {})
    if type(environment) is not dict or environment != expected_env:
        raise Refused("UNREVIEWED_ENVIRONMENT")

    healthcheck = config.get("healthcheck")
    if healthcheck is not None:
        if role != "mcp" or type(healthcheck) is not dict:
            raise Refused("UNREVIEWED_HEALTHCHECK")
        if set(healthcheck) - {
            "test",
            "interval",
            "timeout",
            "retries",
            "start_period",
            "start_interval",
            "disable",
        }:
            raise Refused("UNREVIEWED_HEALTHCHECK")
        if healthcheck.get("test") != _MCP_READINESS_TEST or healthcheck.get("disable") not in (
            None,
            False,
        ):
            raise Refused("UNREVIEWED_HEALTHCHECK")

    # These otherwise-accepted Compose fields can replace protected paths,
    # execute extra commands or exfiltrate logs independently of entrypoint.
    for field in ("tmpfs", "logging", "hostname", "ulimits"):
        if field in config:
            raise Refused("UNREVIEWED_RUNTIME_FIELD")


def _reviewed_service_identity(role: str, config: dict) -> None:
    """Refuse unreviewed deployment participation, UID/GID and launch overrides.

    Only the existing control stack has reviewed static UID/entrypoint pins.
    SSH target bootstrap/sshd identity is NOT reviewed or shipped here: while
    awaiting its own design gate, refuse *all* caller-controlled overrides
    rather than allowing root/alternate shells; image defaults remain untrusted.
    """
    profiles = config.get("profiles", [])
    if type(profiles) is not list:
        raise Refused("INVALID_PROFILE")
    if role in _OPTIONAL_PROFILES:
        if profiles not in ([], _OPTIONAL_PROFILES[role]):
            raise Refused("UNREVIEWED_OPTIONAL_PROFILE")
    elif profiles:
        raise Refused("REQUIRED_SERVICE_PROFILE")

    if "working_dir" in config or "init" in config:
        raise Refused("UNREVIEWED_EXECUTION_OVERRIDE")
    if role in _ROLE_USER:
        if config.get("user") != _ROLE_USER[role]:
            raise Refused("UNREVIEWED_SERVICE_IDENTITY")
        if role == "ledger":
            if config.get("group_add") != ["10003", "10005"]:
                raise Refused("UNREVIEWED_SERVICE_GROUPS")
        elif config.get("group_add") not in (None, []):
            raise Refused("UNREVIEWED_SERVICE_GROUPS")
        if role == "cloudflared":
            if config.get("entrypoint") not in (None,):
                raise Refused("UNREVIEWED_ENTRYPOINT")
            if config.get("command") != _CLOUDFLARED_COMMAND:
                raise Refused("UNREVIEWED_COMMAND")
        else:
            if config.get("entrypoint") != _ROLE_ENTRYPOINT[role]:
                raise Refused("UNREVIEWED_ENTRYPOINT")
            if config.get("command") is not None:
                raise Refused("UNREVIEWED_COMMAND")
    else:
        # Mode A/B SSH targets do not yet have an approved bootstrap image
        # contract. No explicit UID, group or executable overrides are accepted.
        if config.get("user") is not None or config.get("group_add") not in (None, []):
            raise Refused("UNREVIEWED_SSH_TARGET_IDENTITY")
        if config.get("entrypoint") is not None or config.get("command") is not None:
            raise Refused("UNREVIEWED_SSH_TARGET_BOOTSTRAP")


def _hardening(role: str, service: object, defined: dict) -> set[str]:
    config = _dict(service)
    if set(config) - _SUPPORTED_SERVICE:
        raise Refused("UNSUPPORTED_SERVICE_FIELD")
    _reviewed_service_identity(role, config)
    _reviewed_runtime_configuration(role, config)
    if config.get("read_only") is not True:
        raise Refused("READ_ONLY_REQUIRED")
    if config.get("cap_drop") != ["ALL"]:
        raise Refused("CAP_DROP_REQUIRED")
    opts = config.get("security_opt")
    if opts != ["no-new-privileges:true"]:
        raise Refused("NO_NEW_PRIVILEGES_REQUIRED")
    if role == "ledger-init":
        if config.get("cap_add") != ["CHOWN", "DAC_OVERRIDE"]:
            raise Refused("UNREVIEWED_BOOTSTRAP_CAPABILITY")
    elif config.get("cap_add"):
        raise Refused("UNSUPPORTED_CAPABILITY")
    _image(config.get("image"))
    if role in {"ledger", "ledger-init", "approvalctl"}:
        if config.get("network_mode") != "none" or config.get("networks"):
            raise Refused("CONTROL_ISOLATION_REQUIRED")
    elif config.get("network_mode") is not None:
        raise Refused("HOST_OR_CUSTOM_NETWORK_MODE")
    # Explicit network definitions avoid implicit default bridge connectivity.
    networks = _networks(config, defined)
    if role not in {"ledger", "ledger-init", "approvalctl"} and not networks:
        raise Refused("NETWORK_REQUIRED")
    # Ports published on ANY service are not reviewed here; even binding to a
    # private address can be exposed via IP forwarding/NAT.
    mounts = config.get("volumes", [])
    if type(mounts) is not list:
        raise Refused("INVALID_VOLUME")
    for mount in mounts:
        item = _dict(mount)
        kind = item.get("type")
        target = item.get("target")
        source = item.get("source")
        if type(target) is not str or type(source) is not str:
            raise Refused("INVALID_VOLUME")
        if kind not in ("bind", "volume"):
            raise Refused("INVALID_VOLUME")
        if kind == "bind":
            if set(item) - {"type", "source", "target", "read_only", "bind"}:
                raise Refused("UNREVIEWED_BIND_OPTION")
            if item.get("bind") != {"create_host_path": False}:
                # Even an absent bind mapping can have Compose's legacy
                # create_host_path=true default; RO does not prevent creation.
                # Reject SELinux relabels and unreviewed mount propagation too.
                raise Refused("UNREVIEWED_BIND_OPTION")
        else:
            if set(item) - {"type", "source", "target", "read_only", "volume"}:
                raise Refused("UNREVIEWED_VOLUME_OPTION")
            if "volume" in item and item["volume"] != {}:
                raise Refused("UNREVIEWED_VOLUME_OPTION")
        if "//" in target or (kind == "bind" and "//" in source):
            raise Refused("INVALID_VOLUME")
        if kind == "bind" and item.get("read_only") is not True:
            raise Refused("WRITABLE_HOST_BIND")
        if not Path(target).is_absolute() or any(part in {".", ".."} for part in target.split("/")):
            raise Refused("INVALID_VOLUME")
        if kind == "bind" and (
            not Path(source).is_absolute()
            or source == "/"
            or any(part in {".", ".."} for part in source.split("/"))
        ):
            raise Refused("INVALID_VOLUME")
        if any(
            target == path or target.startswith(path + "/")
            for path in (
                "/var/run/docker.sock",
                "/run/docker.sock",
                "/var/run/user",
                "/run/user",
                "/run/containerd",
                "/var/run/containerd",
                "/run/docker",
                "/var/run/docker",
                "/run/podman",
                "/var/run/podman",
                "/run/crio",
                "/var/run/crio",
                "/run/buildkit",
                "/var/run/buildkit",
                "/var/lib/docker",
                "/var/lib/containers",
                "/var/lib/containerd",
                "/var/lib/podman",
                "/var/lib/kubelet",
                "/sys/fs/cgroup",
                "/proc",
                "/sys",
            )
        ):
            raise Refused("UNSAFE_MOUNT")
        if kind == "bind" and _unsafe_rootless_storage_source(source):
            raise Refused("UNSAFE_MOUNT")
        if kind == "bind" and any(
            source == path
            or source.startswith(path + "/")
            or path.startswith(source.rstrip("/") + "/")
            for path in (
                "/var/run/docker.sock",
                "/run/docker.sock",
                "/var/run/user",
                "/run/user",
                "/run/containerd",
                "/var/run/containerd",
                "/run/docker",
                "/var/run/docker",
                "/run/podman",
                "/var/run/podman",
                "/run/crio",
                "/var/run/crio",
                "/run/buildkit",
                "/var/run/buildkit",
                "/var/lib/docker",
                "/var/lib/containers",
                "/var/lib/containerd",
                "/var/lib/podman",
                "/var/lib/kubelet",
                "/sys/fs/cgroup",
                "/proc",
                "/sys",
            )
        ):
            # Read-only access to an enclosing directory still exposes UNIX
            # domain sockets (e.g. /var/run -> docker.sock).
            raise Refused("UNSAFE_MOUNT")
    return networks


_CONTROL_VOLUME_TARGETS = {
    "ledger-data": "/var/lib/ssh-over-mcp",
    "ledger-exec": "/run/ssh-over-mcp-exec",
    "ledger-admin": "/run/ssh-over-mcp-admin",
}
_CONTROL_ROLE_VOLUMES = {
    "ledger-init": frozenset(_CONTROL_VOLUME_TARGETS),
    "ledger": frozenset(_CONTROL_VOLUME_TARGETS),
    "mcp": frozenset({"ledger-exec"}),
    "approvalctl": frozenset({"ledger-admin"}),
    "cloudflared": frozenset(),
}
_CONTROL_ROLE_BIND_TARGETS = {
    "mcp": frozenset(
        {
            "/etc/ssh-over-mcp/config.yaml",
            "/etc/ssh-over-mcp/credentials.yaml",
            "/run/secrets/ssh",
            "/run/secrets/origin-bearer",
        }
    ),
    "cloudflared": frozenset({"/run/secrets/cloudflare-tunnel-token"}),
}


def _control_volume_kind(name: str) -> str | None:
    for reserved in _CONTROL_VOLUME_TARGETS:
        if name == reserved or name.endswith("_" + reserved):
            return reserved
    return None


def _validate_control_mounts(services: dict, volume_identities: dict[str, str]) -> None:
    """Keep admin/ledger socket and database volumes separate by service role."""
    for role, permitted in _CONTROL_ROLE_VOLUMES.items():
        if role not in services:
            continue
        mounts = _dict(services[role]).get("volumes", [])
        if type(mounts) is not list:
            raise Refused("INVALID_VOLUME")
        for mount in mounts:
            item = _dict(mount)
            if item.get("type") != "volume":
                # Lexically validated read-only binds are allowed only to
                # operator inputs, never to the protected Ledger mount targets.
                if any(
                    item.get("target") == target
                    or str(item.get("target", "")).startswith(target + "/")
                    or target.startswith(str(item.get("target", "")).rstrip("/") + "/")
                    for target in _CONTROL_VOLUME_TARGETS.values()
                ):
                    raise Refused("CONTROL_VOLUME_BOUNDARY")
                if item.get("target") not in _CONTROL_ROLE_BIND_TARGETS.get(role, frozenset()):
                    raise Refused("UNREVIEWED_CONTROL_BIND_TARGET")
                continue
            source = item.get("source")
            if type(source) is not str:
                raise Refused("INVALID_VOLUME")
            resolved = volume_identities.get(source, source)
            source_role = _control_volume_kind(source)
            resolved_role = _control_volume_kind(resolved)
            if (
                source_role is None
                or source_role != resolved_role
                or source_role not in permitted
                or item.get("target") != _CONTROL_VOLUME_TARGETS[source_role]
            ):
                raise Refused("CONTROL_VOLUME_BOUNDARY")
            if role in {"mcp", "approvalctl"} and item.get("read_only") is not True:
                raise Refused("CONTROL_VOLUME_READ_ONLY_REQUIRED")


def _control(document: object, mode: str) -> tuple[dict, dict, dict[str, str]]:
    services, networks, volume_identities = _project(document)
    mandatory = _CONTROL | (_TARGET_ROOT if mode == "dev-e2e" else frozenset())
    if not mandatory <= set(services) or not set(services) <= mandatory | _OPTIONAL:
        raise Refused("INVALID_SERVICE_SET")
    for name, service in services.items():
        _hardening(name, service, networks)
    _validate_control_mounts(services, volume_identities)
    if "cloudflared" in services:
        cloudflared_networks = _networks(_dict(services["cloudflared"]), networks)
        if not cloudflared_networks or not cloudflared_networks <= {
            "origin_internal",
            "cloudflare_egress",
        }:
            raise Refused("CLOUDFLARED_NETWORK_BOUNDARY")
    if networks.get("origin_internal", {}).get("internal") is not True:
        raise Refused("UNSAFE_ORIGIN_NETWORK")
    if mode == "dev-e2e":
        expected = {"origin_internal", "node01_ssh", "node02_ssh"}
        if _networks(services["mcp"], networks) != expected:
            raise Refused("INVALID_MCP_NETWORKS")
    else:
        expected = {"origin_internal", "private_ssh_egress"}
        if _networks(services["mcp"], networks) != expected:
            raise Refused("INVALID_MCP_NETWORKS")
    return services, networks, volume_identities


def _target_volumes(
    service: dict, alias: str | None, volume_identities: dict[str, str]
) -> set[str]:
    mounts = service.get("volumes", [])
    if type(mounts) is not list or len(mounts) != 2:
        raise Refused("TARGET_VOLUMES_REQUIRED")
    sources: set[str] = set()
    targets: set[str] = set()
    for mount in mounts:
        item = _dict(mount)
        source = item.get("source")
        target = item.get("target")
        if item.get("type") != "volume" or type(source) is not str or type(target) is not str:
            raise Refused("TARGET_NAMED_VOLUMES_ONLY")
        resolved = volume_identities.get(source, source)
        if (
            not source
            or source in _ADMIN_VOLUMES
            or resolved in _ADMIN_VOLUMES
            or any(resolved.endswith("_" + admin) for admin in _ADMIN_VOLUMES)
            or any(source.endswith("_" + admin) for admin in _ADMIN_VOLUMES)
            or resolved in sources
            or target in targets
        ):
            raise Refused("SHARED_TARGET_VOLUME")
        if alias is not None and not (
            source.startswith(alias + "-") or source.rsplit("_", 1)[-1].startswith(alias + "-")
        ):
            raise Refused("SHARED_TARGET_VOLUME")
        if target not in {"/srv/data", "/etc/ssh/hostkeys"}:
            raise Refused("TARGET_VOLUME_LAYOUT")
        sources.add(resolved)
        targets.add(target)
    if targets != {"/srv/data", "/etc/ssh/hostkeys"}:
        raise Refused("TARGET_VOLUME_LAYOUT")
    return sources


def check_mode_a(document: object) -> None:
    services, networks, volume_identities = _control(document, "dev-e2e")
    all_sources: set[str] = set()
    for alias in ("node01", "node02"):
        allowed = alias + "_ssh"
        if networks.get(allowed, {}).get("internal") is not True:
            raise Refused("UNSAFE_TARGET_NETWORK")
        if _networks(services[alias], networks) != {allowed}:
            raise Refused("TARGET_LATERAL_NETWORK")
        sources = _target_volumes(_dict(services[alias]), alias, volume_identities)
        if sources & all_sources:
            raise Refused("SHARED_TARGET_VOLUME")
        all_sources.update(sources)
    for name in ("ledger-init", "ledger", "mcp", "approvalctl", "cloudflared"):
        if name in services and _dict(services[name]).get("volumes"):
            # Existing control stack has its own admin/ledger volumes, and
            # no node-specific volume may be shared with any such service.
            sources = {
                volume_identities.get(item.get("source"), item.get("source"))
                for item in _dict(services[name]).get("volumes", [])
                if type(item) is dict
            }
            if sources & all_sources:
                raise Refused("SHARED_TARGET_VOLUME")


def check_mode_b(control: object, node01: object, node02: object) -> None:
    _control(control, "multi-host")
    for target in (node01, node02):
        services, networks, volume_identities = _project(target)
        if set(services) != {"ssh-target"} or set(networks) != {"ssh_private"}:
            raise Refused("INVALID_TARGET_PROJECT")
        if networks["ssh_private"].get("internal") is not True:
            raise Refused("UNSAFE_TARGET_NETWORK")
        target_service = _dict(services["ssh-target"])
        if _hardening("ssh-target", target_service, networks) != {"ssh_private"}:
            raise Refused("INVALID_TARGET_NETWORK")
        _target_volumes(target_service, None, volume_identities)
    # Only checks three operator-supplied descriptions, NOT three Engines.


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Offline Docker Compose config JSON structure check, no deployment authority."
    )
    parser.add_argument("--mode", choices=("dev-e2e", "multi-host"), required=True)
    parser.add_argument("--control-json", required=True, type=Path)
    parser.add_argument("--node01-json", type=Path)
    parser.add_argument("--node02-json", type=Path)
    options = parser.parse_args()
    try:
        if options.mode == "dev-e2e":
            if options.node01_json or options.node02_json:
                raise Refused("INVALID_MODE_FILES")
            check_mode_a(_read_one_regular_file(options.control_json))
        else:
            if options.node01_json is None or options.node02_json is None:
                raise Refused("MISSING_TARGET_PROJECT")
            # Same path is never valid proof of separate target project inputs.
            if (
                len(
                    {
                        str(p.absolute())
                        for p in (
                            options.control_json,
                            options.node01_json,
                            options.node02_json,
                        )
                    }
                )
                != 3
            ):
                raise Refused("DUPLICATE_INPUT_PATH")
            check_mode_b(
                _read_one_regular_file(options.control_json),
                _read_one_regular_file(options.node01_json),
                _read_one_regular_file(options.node02_json),
            )
    except (Refused, OSError, TypeError, ValueError, KeyError) as exc:
        code = exc.code if isinstance(exc, Refused) else "INPUT_UNAVAILABLE"
        parser.error("preflight refused: " + code)
    print(
        json.dumps(
            {
                "schema": _REPORT,
                "mode": options.mode,
                "target_count": 2,
                "static_compose_shape_valid": True,
                "deployment_ready": False,
                "host_identity_verified": False,
                "image_trust_verified": False,
                "network_acl_verified": False,
                "runtime_verified": False,
                "live_e2e_verified": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
