from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_GUIDE = _REPO_ROOT / "docs" / "cloudflare-deployment.md"


def _text() -> str:
    return " ".join(_GUIDE.read_text(encoding="utf-8").split())


def test_phase6d_managed_oauth_guidance_keeps_portal_auth_separate_from_origin() -> None:
    text = _text()

    assert "Managed OAuth" in text
    assert "OAuth 2.0 authorization code flow" in text
    assert "enabled by default for new MCP portals" in text
    assert "Advanced settings" in text
    assert "Portal Access application" in text
    assert "Managed OAuth is not the origin bearer" in text
    assert "does not select `SSH_OVER_MCP_PROFILE`" in text
    assert "does not bypass ssh-over-mcp policy or approval" in text


def test_phase6d_service_token_guidance_requires_both_access_checks() -> None:
    text = _text()

    assert "Access service token" in text
    assert "Service Auth" in text
    assert "Portal Access application" in text
    assert "each linked MCP-server Access application" in text
    assert "Require user auth" in text
    assert "`on_behalf=false`" in text
    assert "`CF-Access-Client-Id`" in text
    assert "`CF-Access-Client-Secret`" in text
    assert "per-user OAuth are excluded from service-token sessions" in text
    assert "caller secret storage" in text
    for forbidden_location in (
        "repository files",
        "model prompts",
        "tool arguments",
        "MCP/container environment",
        "application logs",
    ):
        assert forbidden_location in text


def test_phase6d_guide_distinguishes_all_four_credential_classes() -> None:
    text = _text()

    assert "Tunnel token" in text
    assert "origin bearer" in text
    assert "Access service-token ID/secret" in text
    assert "Cloudflare API token" in text
    assert "These four credential classes are not interchangeable" in text


def test_phase6d_multi_profile_guidance_requires_separate_static_instances() -> None:
    text = _text()

    assert "one deployment instance = one static `SSH_OVER_MCP_PROFILE`" in text
    assert "separate Compose project/service instances" in text
    assert "separate private hostnames" in text
    assert "separate origin bearers" in text
    assert "caller never supplies a profile selector" in text
    assert "OAuth claim-to-profile mapping remains deferred beyond Phase 6" in text
    assert "not request headers" in text


def test_phase6d_gateway_dlp_guidance_scopes_observability_correctly() -> None:
    text = _text()

    assert "Gateway HTTP logs" in text
    assert "HTTP/DLP policies" in text
    assert "DLP AI prompt profiles do not apply to MCP Portal traffic" in text
    assert "Logpush/SIEM" in text
    assert "not a replacement for Security Ledger execution audit" in text
    assert "background credential/capability synchronization" in text
    assert "host-agent/OS policy" in text
