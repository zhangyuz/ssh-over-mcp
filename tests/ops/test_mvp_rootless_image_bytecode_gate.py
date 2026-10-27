"""Static fail-closed packaging gate for the OpenSSH FS-only launcher.

This supplements -- but does not substitute for -- a signed OCI image build.
"""

from pathlib import Path

IMAGE = (
    Path(__file__).resolve().parents[2] / "deploy/ssh-target/Dockerfile.fs-only-review-candidate"
)


def test_site_packages_bytecode_removed_after_final_pip_install():
    image = IMAGE.read_text()
    install = image.index("/opt/ssh-over-mcp-e2e/venv/bin/pip install")
    clean = image.index("find /opt/ssh-over-mcp-e2e/venv/lib/python3.14/site-packages")
    assert clean > install, "must scrub bytecode produced by pip/venv"
    assert "-name __pycache__" in image[clean:]
    assert "-name '*.pyc'" in image[clean:]
    assert "-name '*.pyo'" in image[clean:]
    assert "test -z" in image[clean:]
    assert 'ENTRYPOINT ["/usr/local/libexec/ssh-over-mcp-image-hold"]' in image
