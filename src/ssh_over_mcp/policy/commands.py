from __future__ import annotations

import posixpath


SHELLS = {"bash", "sh", "dash", "zsh", "fish", "ksh", "csh", "tcsh"}
INTERPRETERS = {"python", "python3", "perl", "ruby", "node", "php", "lua"}
PACKAGE_MANAGERS = {
    "apt", "apt-get", "dnf", "yum", "apk", "pacman", "pip", "pip3", "npm", "pnpm", "yarn"
}
CONTAINER_RUNTIMES = {"docker", "podman", "nerdctl", "ctr"}
PRIVILEGE_TOOLS = {"sudo", "su", "doas", "pkexec"}
NETWORK_ADMIN = {"iptables", "ip6tables", "nft", "ip", "tc", "route"}
DESTRUCTIVE = {"rm", "unlink", "shred", "mkfs", "wipefs"}
SERVICE_CONTROL = {"systemctl", "service"}


def normalize_executable(executable: str) -> str:
    if not executable.startswith("/"):
        raise ValueError("executable must be an absolute path")
    return posixpath.normpath(executable)


def classify_executable(executable: str | None, tool: str) -> frozenset[str]:
    capabilities: set[str] = set()
    if tool == "ssh_shell":
        capabilities.update({"shell", "arbitrary_code"})
    if tool.startswith("fs_"):
        capabilities.add("filesystem")
        if tool in {"fs_write", "fs_mkdir", "fs_move", "fs_delete"}:
            capabilities.add("filesystem_mutation")
        if tool == "fs_delete":
            capabilities.add("destructive")
    if tool in {"service_action", "process_signal"}:
        capabilities.add("process_control")
    if not executable:
        return frozenset(capabilities)

    name = posixpath.basename(executable)
    if name in SHELLS:
        capabilities.update({"shell", "arbitrary_code"})
    if name in INTERPRETERS:
        capabilities.update({"interpreter", "arbitrary_code"})
    if name in PACKAGE_MANAGERS:
        capabilities.update({"package_manager", "network_client", "arbitrary_code"})
    if name in CONTAINER_RUNTIMES:
        capabilities.update({"container_runtime", "arbitrary_code"})
    if name in PRIVILEGE_TOOLS:
        capabilities.update({"privilege_escalation", "arbitrary_code"})
    if name in NETWORK_ADMIN:
        capabilities.add("network_administration")
    if name in DESTRUCTIVE:
        capabilities.update({"filesystem_mutation", "destructive"})
    if name in SERVICE_CONTROL:
        capabilities.add("service_control")
    return frozenset(capabilities)
