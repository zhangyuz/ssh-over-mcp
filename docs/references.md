# References

These references inform the current architecture. They are informative; the repository's normative behavior is defined by the source-of-truth documents and ADRs.

## Model Context Protocol

- MCP 2026-07-28 specification release: https://blog.modelcontextprotocol.io/posts/2026-07-28/
- MCP specification/documentation: https://modelcontextprotocol.io/
- MCP TypeScript SDK: https://ts.sdk.modelcontextprotocol.io/

## Cloudflare

- MCP server portals: https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/
- Managed OAuth: https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/
- Private MCP server support: https://developers.cloudflare.com/changelog/post/2026-09-22-private-mcp-servers/
- MCP portals GA: https://developers.cloudflare.com/changelog/post/2026-09-24-mcp-portals-ga/
- Service tokens for MCP portals: https://developers.cloudflare.com/changelog/post/2026-06-26-mcp-portal-service-tokens/

## SSH transport

- AsyncSSH 2.24 documentation: https://asyncssh.readthedocs.io/en/latest/
- AsyncSSH API reference: https://asyncssh.readthedocs.io/en/latest/api.html
- AsyncSSH PyPI releases: https://pypi.org/project/asyncssh/

## OpenSSH

- `sshd_config(5)`: https://man.openbsd.org/sshd_config
- `authorized_keys` options are documented through OpenSSH manual pages and should be checked against the deployed OpenSSH version.


## Race-resistant execution

- Python 3.13 `os.execve` / fd support: https://docs.python.org/3.13/library/os.html
- Linux `fexecve(3)`: https://man7.org/linux/man-pages/man3/fexecve.3.html
- Linux `execveat(2)`: https://man7.org/linux/man-pages/man2/execveat.2.html
- Linux `openat2(2)`: https://man7.org/linux/man-pages/man2/openat2.2.html


## Linux cgroup v2 and delegation

- Linux kernel cgroup v2 documentation: https://docs.kernel.org/admin-guide/cgroup-v2.html
- systemd control-group delegation: https://systemd.io/CGROUP_DELEGATION/


## Linux Unix peer authentication

- Linux `unix(7)` / `SO_PEERCRED`: https://man7.org/linux/man-pages/man7/unix.7.html
- Linux `socket(7)`: https://man7.org/linux/man-pages/man7/socket.7.html


## Linux process credentials

- Linux `credentials(7)`: https://man7.org/linux/man-pages/man7/credentials.7.html
- Linux `getresuid(2)` / `getresgid(2)`: https://man7.org/linux/man-pages/man2/getresuid.2.html
- Linux `setresuid(2)` / `setresgid(2)`: https://man7.org/linux/man-pages/man2/setresuid.2.html
