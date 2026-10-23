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


def _dict(value: object) -> dict:
    if type(value) is not dict:
        raise Refused("INVALID_SHAPE")
    return value


def _project(document: object) -> tuple[dict, dict]:
    root = _dict(document)
    if not set(root) <= _SUPPORTED_PROJECT:
        raise Refused("UNSUPPORTED_COMPOSE_FIELD")
    services = _dict(root.get("services"))
    networks = _dict(root.get("networks", {}))
    volumes = _dict(root.get("volumes", {}))
    if len(services) > 8 or len(networks) > 8 or len(volumes) > 16:
        raise Refused("TOO_MANY_ENTRIES")
    resolved_volumes: set[str] = set()
    for name, config in volumes.items():
        if type(name) is not str or type(config) is not dict:
            raise Refused("INVALID_VOLUME")
        if set(config) - {"name", "external"} or config.get("external") not in (None, False):
            raise Refused("UNSUPPORTED_VOLUME")
        resolved = config.get("name", name)
        if type(resolved) is not str or not resolved or resolved in resolved_volumes:
            raise Refused("SHARED_TARGET_VOLUME")
        resolved_volumes.add(resolved)
    resolved_networks: set[str] = set()
    for name, config in networks.items():
        if type(name) is not str or type(config) is not dict:
            raise Refused("INVALID_NETWORK")
        # External/custom driver networks are not an implied ACL/identity proof.
        if config.get("external") or set(config) - {"internal", "name", "driver"}:
            raise Refused("UNSUPPORTED_NETWORK")
        resolved = config.get("name", name)
        if type(resolved) is not str or not resolved or resolved in resolved_networks:
            raise Refused("SHARED_NETWORK_NAME")
        resolved_networks.add(resolved)
    return services, networks


def _networks(service: dict, defined: dict) -> set[str]:
    value = service.get("networks", [])
    if type(value) is list:
        names = value
    elif type(value) is dict:
        names = list(value)
        if any(type(x) is not dict for x in value.values()):
            raise Refused("INVALID_NETWORK")
    else:
        raise Refused("INVALID_NETWORK")
    if any(type(name) is not str for name in names) or len(names) != len(set(names)):
        raise Refused("INVALID_NETWORK")
    if not set(names) <= set(defined):
        raise Refused("INVALID_NETWORK")
    return set(names)


def _hardening(role: str, service: object, defined: dict) -> set[str]:
    config = _dict(service)
    if set(config) - _SUPPORTED_SERVICE:
        raise Refused("UNSUPPORTED_SERVICE_FIELD")
    if config.get("read_only") is not True:
        raise Refused("READ_ONLY_REQUIRED")
    if config.get("cap_drop") != ["ALL"]:
        raise Refused("CAP_DROP_REQUIRED")
    opts = config.get("security_opt")
    if opts != ["no-new-privileges:true"]:
        raise Refused("NO_NEW_PRIVILEGES_REQUIRED")
    if role == "ledger-init":
        if set(config.get("cap_add", [])) - {"CHOWN", "DAC_OVERRIDE"}:
            raise Refused("UNSUPPORTED_CAPABILITY")
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
                "/sys/fs/cgroup",
                "/proc",
                "/sys",
            )
        ):
            raise Refused("UNSAFE_MOUNT")
        if kind == "bind" and any(
            source == path
            or source.startswith(path + "/")
            or path.startswith(source.rstrip("/") + "/")
            for path in (
                "/var/run/docker.sock",
                "/run/docker.sock",
                "/sys/fs/cgroup",
                "/proc",
                "/sys",
            )
        ):
            # Read-only access to an enclosing directory still exposes UNIX
            # domain sockets (e.g. /var/run -> docker.sock).
            raise Refused("UNSAFE_MOUNT")
    return networks


def _control(document: object, mode: str) -> tuple[dict, dict]:
    services, networks = _project(document)
    mandatory = _CONTROL | (_TARGET_ROOT if mode == "dev-e2e" else frozenset())
    if not mandatory <= set(services) or not set(services) <= mandatory | _OPTIONAL:
        raise Refused("INVALID_SERVICE_SET")
    for name, service in services.items():
        _hardening(name, service, networks)
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
    return services, networks


def _target_volumes(service: dict, alias: str | None) -> set[str]:
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
        if (
            not source
            or source in _ADMIN_VOLUMES
            or any(source.endswith("_" + admin) for admin in _ADMIN_VOLUMES)
            or source in sources
            or target in targets
        ):
            raise Refused("SHARED_TARGET_VOLUME")
        if alias is not None and not (
            source.startswith(alias + "-") or source.rsplit("_", 1)[-1].startswith(alias + "-")
        ):
            raise Refused("SHARED_TARGET_VOLUME")
        if target not in {"/srv/data", "/etc/ssh/hostkeys"}:
            raise Refused("TARGET_VOLUME_LAYOUT")
        sources.add(source)
        targets.add(target)
    if targets != {"/srv/data", "/etc/ssh/hostkeys"}:
        raise Refused("TARGET_VOLUME_LAYOUT")
    return sources


def check_mode_a(document: object) -> None:
    services, networks = _control(document, "dev-e2e")
    all_sources: set[str] = set()
    for alias in ("node01", "node02"):
        allowed = alias + "_ssh"
        if networks.get(allowed, {}).get("internal") is not True:
            raise Refused("UNSAFE_TARGET_NETWORK")
        if _networks(services[alias], networks) != {allowed}:
            raise Refused("TARGET_LATERAL_NETWORK")
        sources = _target_volumes(_dict(services[alias]), alias)
        if sources & all_sources:
            raise Refused("SHARED_TARGET_VOLUME")
        all_sources.update(sources)
    for name in ("ledger-init", "ledger", "mcp", "approvalctl", "cloudflared"):
        if name in services and _dict(services[name]).get("volumes"):
            # Existing control stack has its own admin/ledger volumes, and
            # no node-specific volume may be shared with any such service.
            sources = {
                item.get("source")
                for item in _dict(services[name]).get("volumes", [])
                if type(item) is dict
            }
            if sources & all_sources:
                raise Refused("SHARED_TARGET_VOLUME")


def check_mode_b(control: object, node01: object, node02: object) -> None:
    _control(control, "multi-host")
    for target in (node01, node02):
        services, networks = _project(target)
        if set(services) != {"ssh-target"} or set(networks) != {"ssh_private"}:
            raise Refused("INVALID_TARGET_PROJECT")
        if networks["ssh_private"].get("internal") is not True:
            raise Refused("UNSAFE_TARGET_NETWORK")
        target_service = _dict(services["ssh-target"])
        if _hardening("ssh-target", target_service, networks) != {"ssh_private"}:
            raise Refused("INVALID_TARGET_NETWORK")
        _target_volumes(target_service, None)
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
