"""CI-only build of distinct runnable Mode A FS pilot image candidate.

The signed STOP78 test image and its archive are never changed or promoted.
No shared Yuz.local daemon is accessed. This build is only on a disposable
GitHub-hosted runner, not an approved production image.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from mode_a_hosted_native_review import stage
from mode_a_hosted_oci_fs_smoke import run

IMAGE = "som-mvp-fs-online-pilot-review:local"
DOCKERFILE = """FROM som-mvp-fs-privsep:local
COPY --chown=0:0 --chmod=0555 fs-only-native-review.py /usr/local/libexec/ssh-over-mcp-fs-only-native-review.py
COPY --chown=0:0 --chmod=0644 sshd_config.native-review /etc/ssh/sshd_config
USER 0:0
ENTRYPOINT ["/usr/sbin/sshd"]
CMD ["-D","-e"]
"""


def main() -> None:
    assert os.getenv("GITHUB_ACTIONS") == "true"
    assert os.getenv("RUNNER_ENVIRONMENT") == "github-hosted"
    assert os.getenv("GITHUB_EVENT_NAME") == "pull_request"
    assert os.getenv("RUNNER_TEMP")
    with tempfile.TemporaryDirectory(
        prefix="som342-online-pilot-build-", dir=os.environ["RUNNER_TEMP"]
    ) as tmp:
        context = Path(tmp)
        assert len(stage(context)) == 4
        (context / "Dockerfile").write_text(DOCKERFILE)
        run(
            [
                "docker",
                "build",
                "--network",
                "none",
                "--no-cache",
                "-f",
                str(context / "Dockerfile"),
                "-t",
                IMAGE,
                str(context),
            ],
            timeout=140,
        )
    result = run(["docker", "image", "inspect", IMAGE, "--format", "{{json .Config}}"])
    config = json.loads(result.stdout)
    assert config["Entrypoint"] == ["/usr/sbin/sshd"]
    assert config["Cmd"] == ["-D", "-e"]
    assert config["User"] == "0:0"
    assert "2222/tcp" in config["ExposedPorts"]
    print("HOSTED_ONLINE_PILOT_RUNNABLE_IMAGE_BUILD_ONLY_PASS", flush=True)
    print("SIGNED_RUNTIME_ID=false PRODUCTION_RELEASE_AUTHORIZED=false", flush=True)


if __name__ == "__main__":
    main()
