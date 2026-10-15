# ADR 0019 Gate B0a — synthetic candidate research evidence (NOT SOURCE_APPROVED)

**Evidence date:** 2026-10-15 (T5A acquisition snapshot only).
**PR:** [#268](https://github.com/zhangyuz/ssh-over-mcp/pull/268).
**Authority:** `NON_AUTHORIZING_SYNTHETIC`; **T5B UNAPPROVED**, real Sigstore cryptographic GREEN/RED **NOT EXECUTED**, real macOS B0–B4/UID502/APFS **UNVERIFIED**. This is not an installer/source admission record.

## What was actually measured (T5A, inspection-only)

- Non-privileged disposable Linux x86_64 / CPython **3.14.4** research guest; public candidate retrieval with `python3 -m pip download --only-binary=:all: sigstore==4.3.0` into `/tmp/som-pr268-t5a-candidates-20261015/wheels`. No install, import, verifier invocation, installer, privileges or Python.org macOS `.pkg`/bundle retrieval.
- Exact **31** downloaded wheel bytes and sizes were hashed in that guest and individually compared against the corresponding PyPI project/version JSON. **31/31 SHA-256 and 31/31 size equality**, no PyPI-yanked release in the chosen set, no absolute/`..` ZIP member names or compressed extracted-size budget excess observed. Checks show **PyPI metadata agreement, not independent publisher/source/build trust**.
- Primary `sigstore-4.3.0-py3-none-any.whl`: **111,351 bytes**, SHA-256 `0f60c46c92fd4e871fbec979c9ae2aa381d7a93fbb774e49c9964550e5e16856`. [Upstream PyPI candidate](https://pypi.org/project/sigstore/4.3.0/) reports a publishing attestation from `sigstore/sigstore-python` release commit `4baa76f7b30ec416d4bba66defc325d5c36dfb20`; that attestation has **not** been independently cryptographically verified here. No interpreter/loader/base-image or transitive closure approval.
- Guest-local detailed T5A audit: `/tmp/som-pr268-t5a-candidates-20261015/manifest.sha256` and `pypi-crosscheck.json`. The following literal SHA manifest is also in [PR evidence comment #6202554795](https://github.com/zhangyuz/ssh-over-mcp/pull/268#issuecomment-6202554795). This is a **candidate snapshot**, not an executable whitelist.

```text
f072f4d804ea359e4eaf198b1af7a8b0943881a87f31bb764f8bf219bb9419e0  annotated_types-0.8.0-py3-none-any.whl
62f22742b58a1a33014a2b6b706588a8d7e2a88ae7bd1a6ebe8c992928483775  certifi-2026.7.22-py3-none-any.whl
b0431303acaea1089ad4b3e9ce4e6518193def1118d4073ca848635ee4ea2e96  cffi-2.1.1-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.whl
34276fd796040bf0993ab33a369aa572e6979c7aab225a88893667ad8eac8f7a  charset_normalizer-3.5.2-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl
0ee6ea481db1ab889cba043ec1eda17bb9c1ea79db6722f779c3667f9f70322f  cryptography-48.0.1-cp311-abi3-manylinux_2_34_x86_64.whl
9a4aedb833c3c1b49214d04d44d3032ab7a9135f7c1d29a549b4ff78fd82fda9  dnspython-2.9.0-py3-none-any.whl
80f13f623413e6b197ae73bb10bf4eb0908faf509ad8362c5edeb0be7fd450b4  email_validator-2.3.0-py3-none-any.whl
f5ec41ed2629a508f5d0988eda142e190c9c6da971100612c4de9ad9f9b237ca  id-1.6.1-py3-none-any.whl
ab7ae7122974553370f0bdb919e1a960b2cd1bc1ef0276416d896db81c14582c  idna-3.20-py3-none-any.whl
9f7ebbcd14fe59494226453aed97c1070d83f8d24b6fc3a3bcf9a38092641c4a  markdown_it_py-4.2.0-py3-none-any.whl
84008a41e51615a49fc9966191ff91509e3c40b939176e643fd50a5c2196b8f8  mdurl-0.1.2-py3-none-any.whl
3dbcf4cd708f21cf876c4eaa90e58412bc4f033d87143f41b1493ff77c25b7e1  platformdirs-4.13.0-py3-none-any.whl
deda9277cfd454080ec40b207fb6df82206a3a2688735233cdcd8d3d565f088b  pyasn1-0.6.4-py3-none-any.whl
51d5a8ba2be0bbe440b99d2112604c95bbbc3c2748a64260186c541e1729cd80  pycparser-3.11-py3-none-any.whl
9195d967ec791692a04438115466764fb8b9a27b31f14a760437694f40d6b454  pydantic-2.14.1-py3-none-any.whl
42b54c2c90ad348b5e3a85e03e715d572c1fde357ef104cdfe3b03b697a404ea  pydantic_core-2.50.1-cp314-cp314-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
2363c69b61c4a97c838da3b130dcd6468f4848992b21a82f2a63ec34377137d9  pygments-2.21.0-py3-none-any.whl
42d59d631f7768a1028a64c7ff581a9bf7519804daf91fc5b6c56e30eec5e193  pyjwt-2.15.1-py3-none-any.whl
4f9d971bc5298b8bc1fab282803da04bf000c755d4ad9d99b52de2569ca19a70  pyopenssl-26.2.0-py3-none-any.whl
2a0d60c172f83ac6ab31e4554906c0f3b3588d37b5cb939b1c061f4907e278e0  requests-2.34.2-py3-none-any.whl
fac3f440a507555e684dc5daba75e33dc08f0f45fdefa48448f19001233a6b21  rfc3161_client-1.0.9-cp39-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
520d690b448ecf0703691c76e1a34a24ddcd4fc5bc41d589cb7c58ec651bcd48  rfc8785-0.1.4-py3-none-any.whl
33bd4ef74232fb73fe9279a257718407f169c09b78a87ad3d296f548e27de0bb  rich-15.0.0-py3-none-any.whl
ada8bdf817da29ece4ba91654f6a162ce7cfbadbc3ae3f840f7313f9d22675de  securesystemslib-1.5.1-py3-none-any.whl
0f60c46c92fd4e871fbec979c9ae2aa381d7a93fbb774e49c9964550e5e16856  sigstore-4.3.0-py3-none-any.whl
5201a68f4d7d0f8bec1e2f4378eb646b084c52609a4e31db8c385095fff68b2e  sigstore_models-0.0.6-py3-none-any.whl
b62bf38c5b1a62bc0d7fe0ee51a0709e49311d137c7880c329882a8f4b2d1d78  sigstore_rekor_types-0.0.18-py3-none-any.whl
d30434bda6e079ab303fb30d1b3006d939a10ca34783b1573d61cd9b802fa45c  tuf-7.0.1-py3-none-any.whl
481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8  typing_extensions-4.16.0-py3-none-any.whl
65b8397ba37ccbce054456aaccddfc91e6e3083c92824df348d96ca832f3f147  typing_inspection-0.4.4-py3-none-any.whl
0cf3cae568d36aa9576b28dfb35f11328f1cb974ca7647d9475ebb86c75ac6e3  urllib3-2.8.0-py3-none-any.whl
```

## Independently identifiable signed-test candidate (NOT VERIFIED)

Official [Sigstore conformance repository snapshot](https://github.com/sigstore/sigstore-conformance/tree/e241c4ea6c83b4d8f03461e825f056b2c5eba3ed/test/assets/bundle-verify/rekor2-happy-path) at commit `e241c4ea6c83b4d8f03461e825f056b2c5eba3ed`:

| Candidate bytes | Measured SHA-256 | Length |
| --- | --- | ---: |
| `test/assets/bundle-verify/a.txt` | `a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf` | 109 |
| `rekor2-happy-path/bundle.sigstore.json` | `3a5ce62cee2653969be846a41e8332eae82c633cdfafe6db48b10e60939518dd` | 10,123 |
| `rekor2-happy-path/trusted_root.json` | `ed6a9cf4e7c2e3297a4b5974fce0d17132f03c63512029d7aa3a402b43acab49` | 6,824 |

The historical **Sigstore bundle v0.3** is `messageSignature`, Rekor v2 `hashedrekord 0.0.2` with a claimed inclusion proof/checkpoint and **one RFC3161 timestamp**. The declared SHA2_256 digest agrees with the separately SHA-256-measured 109-byte artifact; **no cryptographic certificate/SCT/Rekor/TSA or signature verification was executed**.

Candidate signing SAN (from conformance defaults): `https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main`; candidate issuer `https://token.actions.githubusercontent.com`. Both remain **unapproved expectations**.

The candidate `trusted_root.json` came **from the same Git repository** as the bundle. It is *not* an independent authenticated trust anchor. Explicitly acquire and validate keys/CA/CT/log/TSA/time independently before authority.

## Important T5B config-format incompatibility: no root-file shortcut

The [exact proposed sigstore-python 4.3.0 release-source CLI](https://github.com/sigstore/sigstore-python/blob/4baa76f7b30ec416d4bba66defc325d5c36dfb20/sigstore/_cli.py) uses `ClientTrustConfig.from_json(args.trust_config.read_text())` for `--trust-config`. The conformance case offers **only a `trusted_root.json`**, *not* a complete `ClientTrustConfig`. Passing that file directly as `--trust-config` is an **invalid trust configuration**; do not silently use `--staging` or embedded/cached TUF as a fallback. T5B must independently authenticate a **complete ClientTrustConfig** (trusted root **and** signing config fields accepted by this exact version), pin its exact bytes and independently selected validity policy **before verifier invocation**.

The [offline CLI guidance](https://sigstore.github.io/sigstore-python/advanced/offline/) warns that `--offline` alone can fall back to stale cached/embedded TUF keys; the execution environment also requires outer network denial, explicit absolute paths and no ambient credentials or uncontrolled runtime loader.

## Gate matrix and outstanding decisions

| Gate | Evidence / current result |
| --- | --- |
| D1/D2 design and path scope | Reviewed and operator-approved in [PR #268](https://github.com/zhangyuz/ssh-over-mcp/pull/268) |
| Current synthetic-only code security review | [CLEAN 0/0/0 at `c6aa61f`](https://github.com/zhangyuz/ssh-over-mcp/pull/268#issuecomment-6201280667) — interim scope only |
| Exact-HEAD hosted CI at `c6aa61f` | [`38798636841` SUCCESS](https://github.com/zhangyuz/ssh-over-mcp/actions/runs/38798636841) — NOT a signed-source GREEN |
| T5A provenance/candidate inspection | **31/31 PyPI metadata consistency**; partial provenance evidence above |
| T5B independent verifier/interpreter/dependency/loader identity | **UNRESOLVED / NOT APPROVED** |
| T5B independently authenticated test root/signature/SAN/OIDC/Rekor/CT/TSA | **UNRESOLVED / NOT APPROVED** |
| T5B complete `ClientTrustConfig`, trusted clock, numeric skew/root freshness/revocation, single sealed digest-vs-FD mode | **UNRESOLVED / NOT APPROVED** |
| Real pinned-offline-verifier synthetic GREEN plus paired signed/digest/root/time RED | **NOT EXECUTED; no GREEN claim** |
| B0b / macOS physical UID502/APFS acceptance | **UNVERIFIED**, separately gated |

**No READY or MERGE** until the exact T5B independent security and operator decision is recorded; actual execution is separately authorized; real cryptographic positive and adversarial negatives plus final independent review and exact-head CI are available. Never use this T5A manifest, same-repo staging root, CLI `B0A_REFUSED`, or CI green as a real `SOURCE_VERIFIED` result.
