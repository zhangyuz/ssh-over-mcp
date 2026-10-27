"""Offline rendered Mode A FS-only Compose gate; never starts containers.

A green shape is NOT a deployment approval, network ACL proof or image trust.
Only load a bounded pre-rendered Compose JSON file, not credentials or keys.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import stat
from pathlib import Path

_HOLD = ["/usr/local/libexec/ssh-over-mcp-image-hold"]
_CAPS = {"SETUID", "SETGID", "SETPCAP", "SYS_CHROOT"}
_RFC1918 = tuple(
    ipaddress.IPv4Network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_IMAGE = re.compile(r"[a-zA-Z0-9._:/-]+@sha256:[0-9a-f]{64}\Z")


class Refused(ValueError):
    """A rendered deployment shape is outside the narrow offline contract."""


def require(ok: object, code: str) -> None:
    if ok is not True:
        raise Refused(code)


def _image_pinned(value: object) -> bool:
    return isinstance(value, str) and bool(_IMAGE.fullmatch(value))


def inspect_rendered(document: object) -> dict:
    require(type(document) is dict, "INVALID_RENDER")
    services = document.get("services")
    networks = document.get("networks")
    require(type(services) is dict and type(networks) is dict, "INVALID_SHAPE")
    require(
        {"mcp", "node01", "node02", "ledger", "ledger-init"} <= set(services), "MISSING_SERVICE"
    )
    require({"origin_internal", "node01_ssh", "node02_ssh"} <= set(networks), "MISSING_NETWORK")
    for role in ("origin_internal", "node01_ssh", "node02_ssh"):
        net = networks[role]
        require(type(net) is dict and net.get("internal") is True, "NONPRIVATE_BRIDGE")
        require(
            not net.get("external") and net.get("driver") in (None, "bridge"), "UNREVIEWED_BRIDGE"
        )

    origin = networks["origin_internal"]
    ipam = origin.get("ipam", {})
    require(type(ipam) is dict, "INVALID_ORIGIN_IPAM")
    cidr_entries = ipam.get("config")
    require(type(cidr_entries) is list and len(cidr_entries) == 1, "INVALID_ORIGIN_IPAM")
    cfg = cidr_entries[0]
    require(type(cfg) is dict and set(cfg) == {"subnet"}, "INVALID_ORIGIN_IPAM")
    try:
        subnet = ipaddress.IPv4Network(cfg["subnet"], strict=True)
    except (ValueError, TypeError, KeyError) as exc:
        raise Refused("INVALID_ORIGIN_CIDR") from exc
    require(any(subnet.subnet_of(allowed) for allowed in _RFC1918), "ORIGIN_NOT_RFC1918")

    control = services["mcp"]
    require(type(control) is dict, "INVALID_CONTROL")
    ctl_nets = control.get("networks")
    require(
        type(ctl_nets) is dict and set(ctl_nets) == {"origin_internal", "node01_ssh", "node02_ssh"},
        "CONTROL_NETWORKS",
    )
    ip_entry = ctl_nets["origin_internal"]
    require(
        type(ip_entry) is dict and type(ip_entry.get("ipv4_address")) is str, "MISSING_ORIGIN_IP"
    )
    try:
        listener = ipaddress.IPv4Address(ip_entry["ipv4_address"])
    except ipaddress.AddressValueError as exc:
        raise Refused("INVALID_ORIGIN_IP") from exc
    # The Docker bridge normally reserves network+1 as gateway. Avoid it even
    # when Compose doesn't explicitly declare it; reject network/broadcast.
    require(
        listener in subnet
        and listener
        not in (subnet.network_address, subnet.broadcast_address, subnet.network_address + 1),
        "ORIGIN_IP_OUTSIDE_USABLE_SUBNET",
    )
    env = control.get("environment")
    require(
        type(env) is dict and env.get("SSH_OVER_MCP_BIND_HOST") == str(listener),
        "ORIGIN_BIND_MISMATCH",
    )
    require(control.get("user") == "10001:10003", "CONTROL_IDENTITY")
    require(control.get("entrypoint") == ["ssh-over-mcp-server"], "CONTROL_ENTRYPOINT")
    require(
        control.get("read_only") is True and control.get("cap_drop") == ["ALL"], "CONTROL_PRIVILEGE"
    )
    require(control.get("security_opt") == ["no-new-privileges:true"], "CONTROL_NNP")
    hc = control.get("healthcheck", {})
    require(
        type(hc) is dict
        and "SSH_OVER_MCP_BIND_HOST"
        in " ".join(hc.get("test", []) if type(hc.get("test")) is list else []),
        "ORIGIN_HEALTHCHECK",
    )

    ctrl_image = control.get("image")
    require(_image_pinned(ctrl_image), "UNPINNED_CONTROL_IMAGE")
    for role in ("ledger-init", "ledger", "mcp", "approvalctl"):
        if role in services:
            require(services[role].get("image") == ctrl_image, "CONTROL_IMAGE_MISMATCH")

    for role in ("mcp", "node01", "node02"):
        svc = services[role]
        require(type(svc) is dict and not svc.get("ports"), "PUBLISHED_SERVICE_PORT")
        require(svc.get("network_mode") not in ("host", "service:mcp"), "UNSAFE_NETWORK_MODE")
        mounts = svc.get("volumes", [])
        require(type(mounts) is list, "INVALID_MOUNTS")
        for mount in mounts:
            require(type(mount) is dict, "INVALID_MOUNT")
            if mount.get("type") == "bind":
                require(
                    mount.get("read_only") is True
                    and mount.get("bind", {}).get("create_host_path") is False,
                    "AUTO_CREATED_OR_WRITABLE_HOST_PATH",
                )
            else:
                require(mount.get("type") == "volume", "UNREVIEWED_MOUNT")

    for suffix in ("01", "02"):
        role = "node" + suffix
        svc = services[role]
        require(_image_pinned(svc.get("image")), "UNPINNED_SSH_IMAGE")
        require(set(svc.get("networks", {})) == {role + "_ssh"}, "NODE_LATERAL_NETWORK")
        require(svc.get("profiles") == ["mvp-fs-review"], "SSH_PROFILE")
        require(svc.get("user") == "0:0" and svc.get("read_only") is True, "SSH_PRIVILEGE")
        require(svc.get("cap_drop") == ["ALL"] and set(svc.get("cap_add", [])) == _CAPS, "SSH_CAPS")
        require(svc.get("security_opt") == ["no-new-privileges:true"], "SSH_NNP")
        require(svc.get("entrypoint") == _HOLD, "STOP78_REMOVED")
        require(svc.get("expose") == ["2222"], "SSH_PORT")
        mounts = {m.get("target"): m for m in svc.get("volumes", [])}
        require(
            set(mounts) == {"/srv/data", "/etc/ssh/hostkeys", "/etc/ssh/authorized_keys"},
            "SSH_MOUNTS",
        )
        for target in ("/etc/ssh/hostkeys", "/etc/ssh/authorized_keys"):
            mount = mounts[target]
            require(
                mount.get("type") == "bind"
                and mount.get("read_only") is True
                and mount.get("bind", {}).get("create_host_path") is False,
                "SSH_KEY_MOUNT",
            )
        require(
            mounts["/srv/data"].get("type") == "volume"
            and mounts["/srv/data"].get("source") == role + "-data",
            "SSH_DATA_MOUNT",
        )

    return {
        "schema": "som-mode-a-render-review-v1",
        "status": "REVIEW_ONLY_HOLD",
        "origin_rfc1918_inside_subnet": True,
        "network_shape": "THREE_ISOLATED_BRIDGES",
        "runtime_started": False,
        "network_acl_verified": False,
        "deployment_ready": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Read-only, refusal-first Mode A rendered Compose review."
    )
    parser.add_argument("--rendered-json", type=Path, required=True)
    args = parser.parse_args()
    try:
        st = args.rendered_json.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_size <= 512 * 1024, "INVALID_RENDER_FILE")
        data = json.loads(args.rendered_json.read_text(encoding="utf-8"))
        print(json.dumps(inspect_rendered(data), sort_keys=True))
    except (OSError, ValueError, UnicodeError) as exc:
        code = str(exc) if isinstance(exc, Refused) else "INVALID_RENDER_FILE"
        print(
            json.dumps(
                {"schema": "som-mode-a-render-review-v1", "status": "REFUSED", "reason": code},
                sort_keys=True,
            )
        )
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
