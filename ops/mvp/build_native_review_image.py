"""Build exact no-sudo FS review layer from the already-tested native generator.

Only disposable same-repo PR GitHub-hosted Ubuntu. Generates source from the
unchanged five-zero launcher with one asserted gate change, and bakes the
test-only candidate into a STOP78 image. Never starts this image or changes
a production Docker daemon.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from mode_a_hosted_native_review import stage
from mode_a_hosted_oci_fs_smoke import run

NATIVE_IMAGE = "som-mvp-fs-native-review:local"

DOCKERFILE = """FROM som-mvp-fs-privsep:local
COPY --chown=0:0 --chmod=0555 fs-only-native-review.py /usr/local/libexec/ssh-over-mcp-fs-only-native-review.py
COPY --chown=0:0 --chmod=0644 sshd_config.native-review /etc/ssh/sshd_config
USER 0:0
ENTRYPOINT ["/usr/local/libexec/ssh-over-mcp-image-hold"]
"""


def main() -> None:
    assert os.getenv("GITHUB_ACTIONS") == "true"
    assert os.getenv("RUNNER_ENVIRONMENT") == "github-hosted"
    assert os.getenv("GITHUB_EVENT_NAME") == "pull_request"
    assert os.getenv("RUNNER_TEMP")
    with tempfile.TemporaryDirectory(
        prefix="som342-native-image-", dir=os.environ["RUNNER_TEMP"]
    ) as tmp:
        context = Path(tmp)
        generated = stage(context)
        assert len(generated) == 4
        assert (context / "fs-only-native-review.py").is_file()
        assert (context / "sshd_config.native-review").is_file()
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
                NATIVE_IMAGE,
                str(context),
            ],
            timeout=130,
        )
    assert (
        run(
            [
                "docker",
                "image",
                "inspect",
                NATIVE_IMAGE,
                "--format",
                "{{json .Config.Entrypoint}}",
            ]
        ).stdout.strip()
        == b'["/usr/local/libexec/ssh-over-mcp-image-hold"]'
    )
    assert (
        run(
            [
                "docker",
                "image",
                "inspect",
                NATIVE_IMAGE,
                "--format",
                "{{.Config.User}}",
            ]
        ).stdout.strip()
        == b"0:0"
    )
    print("TEST_ONLY_NATIVE_NOSUDO_IMAGE_BAKED_STOP78_PASS", flush=True)


if __name__ == "__main__":
    main()
