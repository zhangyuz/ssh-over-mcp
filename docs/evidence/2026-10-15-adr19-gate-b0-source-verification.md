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

### T5A per-wheel measured-size and PyPI release-metadata audit receipt

The guest recorded each downloaded wheel's **actual on-disk byte length** and SHA-256 separately from each corresponding PyPI project/version JSON release record. Every listed exact filename was found once in that release's `urls[]`, with matching `digests.sha256` and `size`; `yanked=false` for all 31. Source metadata links are the exact project-version JSON endpoints used for comparison; they are **publisher-supplied metadata**, not independent proof of build provenance or trust authorization. This is a fixed **2026-10-15 observation**, not an assertion about current availability or any future resolution.

| Exact candidate wheel filename | Measured SHA-256 | Measured length (bytes) | PyPI `urls[].size` (bytes) | Source metadata |
| --- | --- | ---: | ---: | --- |
| `annotated_types-0.8.0-py3-none-any.whl` | `f072f4d804ea359e4eaf198b1af7a8b0943881a87f31bb764f8bf219bb9419e0` | 13427 | 13427 | [PyPI annotated-types 0.8.0](https://pypi.org/pypi/annotated-types/0.8.0/json) |
| `certifi-2026.7.22-py3-none-any.whl` | `62f22742b58a1a33014a2b6b706588a8d7e2a88ae7bd1a6ebe8c992928483775` | 136983 | 136983 | [PyPI certifi 2026.7.22](https://pypi.org/pypi/certifi/2026.7.22/json) |
| `cffi-2.1.1-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.whl` | `b0431303acaea1089ad4b3e9ce4e6518193def1118d4073ca848635ee4ea2e96` | 221525 | 221525 | [PyPI cffi 2.1.1](https://pypi.org/pypi/cffi/2.1.1/json) |
| `charset_normalizer-3.5.2-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl` | `34276fd796040bf0993ab33a369aa572e6979c7aab225a88893667ad8eac8f7a` | 255056 | 255056 | [PyPI charset-normalizer 3.5.2](https://pypi.org/pypi/charset-normalizer/3.5.2/json) |
| `cryptography-48.0.1-cp311-abi3-manylinux_2_34_x86_64.whl` | `0ee6ea481db1ab889cba043ec1eda17bb9c1ea79db6722f779c3667f9f70322f` | 4745488 | 4745488 | [PyPI cryptography 48.0.1](https://pypi.org/pypi/cryptography/48.0.1/json) |
| `dnspython-2.9.0-py3-none-any.whl` | `9a4aedb833c3c1b49214d04d44d3032ab7a9135f7c1d29a549b4ff78fd82fda9` | 354822 | 354822 | [PyPI dnspython 2.9.0](https://pypi.org/pypi/dnspython/2.9.0/json) |
| `email_validator-2.3.0-py3-none-any.whl` | `80f13f623413e6b197ae73bb10bf4eb0908faf509ad8362c5edeb0be7fd450b4` | 35604 | 35604 | [PyPI email-validator 2.3.0](https://pypi.org/pypi/email-validator/2.3.0/json) |
| `id-1.6.1-py3-none-any.whl` | `f5ec41ed2629a508f5d0988eda142e190c9c6da971100612c4de9ad9f9b237ca` | 14689 | 14689 | [PyPI id 1.6.1](https://pypi.org/pypi/id/1.6.1/json) |
| `idna-3.20-py3-none-any.whl` | `ab7ae7122974553370f0bdb919e1a960b2cd1bc1ef0276416d896db81c14582c` | 69583 | 69583 | [PyPI idna 3.20](https://pypi.org/pypi/idna/3.20/json) |
| `markdown_it_py-4.2.0-py3-none-any.whl` | `9f7ebbcd14fe59494226453aed97c1070d83f8d24b6fc3a3bcf9a38092641c4a` | 91687 | 91687 | [PyPI markdown-it-py 4.2.0](https://pypi.org/pypi/markdown-it-py/4.2.0/json) |
| `mdurl-0.1.2-py3-none-any.whl` | `84008a41e51615a49fc9966191ff91509e3c40b939176e643fd50a5c2196b8f8` | 9979 | 9979 | [PyPI mdurl 0.1.2](https://pypi.org/pypi/mdurl/0.1.2/json) |
| `platformdirs-4.13.0-py3-none-any.whl` | `3dbcf4cd708f21cf876c4eaa90e58412bc4f033d87143f41b1493ff77c25b7e1` | 32724 | 32724 | [PyPI platformdirs 4.13.0](https://pypi.org/pypi/platformdirs/4.13.0/json) |
| `pyasn1-0.6.4-py3-none-any.whl` | `deda9277cfd454080ec40b207fb6df82206a3a2688735233cdcd8d3d565f088b` | 84410 | 84410 | [PyPI pyasn1 0.6.4](https://pypi.org/pypi/pyasn1/0.6.4/json) |
| `pycparser-3.11-py3-none-any.whl` | `51d5a8ba2be0bbe440b99d2112604c95bbbc3c2748a64260186c541e1729cd80` | 51178 | 51178 | [PyPI pycparser 3.11](https://pypi.org/pypi/pycparser/3.11/json) |
| `pydantic-2.14.1-py3-none-any.whl` | `9195d967ec791692a04438115466764fb8b9a27b31f14a760437694f40d6b454` | 488106 | 488106 | [PyPI pydantic 2.14.1](https://pypi.org/pypi/pydantic/2.14.1/json) |
| `pydantic_core-2.50.1-cp314-cp314-manylinux_2_17_x86_64.manylinux2014_x86_64.whl` | `42b54c2c90ad348b5e3a85e03e715d572c1fde357ef104cdfe3b03b697a404ea` | 2159857 | 2159857 | [PyPI pydantic_core 2.50.1](https://pypi.org/pypi/pydantic_core/2.50.1/json) |
| `pygments-2.21.0-py3-none-any.whl` | `2363c69b61c4a97c838da3b130dcd6468f4848992b21a82f2a63ec34377137d9` | 1250147 | 1250147 | [PyPI Pygments 2.21.0](https://pypi.org/pypi/Pygments/2.21.0/json) |
| `pyjwt-2.15.1-py3-none-any.whl` | `42d59d631f7768a1028a64c7ff581a9bf7519804daf91fc5b6c56e30eec5e193` | 33860 | 33860 | [PyPI PyJWT 2.15.1](https://pypi.org/pypi/PyJWT/2.15.1/json) |
| `pyopenssl-26.2.0-py3-none-any.whl` | `4f9d971bc5298b8bc1fab282803da04bf000c755d4ad9d99b52de2569ca19a70` | 55823 | 55823 | [PyPI pyOpenSSL 26.2.0](https://pypi.org/pypi/pyOpenSSL/26.2.0/json) |
| `requests-2.34.2-py3-none-any.whl` | `2a0d60c172f83ac6ab31e4554906c0f3b3588d37b5cb939b1c061f4907e278e0` | 73075 | 73075 | [PyPI requests 2.34.2](https://pypi.org/pypi/requests/2.34.2/json) |
| `rfc3161_client-1.0.9-cp39-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl` | `fac3f440a507555e684dc5daba75e33dc08f0f45fdefa48448f19001233a6b21` | 2415566 | 2415566 | [PyPI rfc3161-client 1.0.9](https://pypi.org/pypi/rfc3161-client/1.0.9/json) |
| `rfc8785-0.1.4-py3-none-any.whl` | `520d690b448ecf0703691c76e1a34a24ddcd4fc5bc41d589cb7c58ec651bcd48` | 9240 | 9240 | [PyPI rfc8785 0.1.4](https://pypi.org/pypi/rfc8785/0.1.4/json) |
| `rich-15.0.0-py3-none-any.whl` | `33bd4ef74232fb73fe9279a257718407f169c09b78a87ad3d296f548e27de0bb` | 310654 | 310654 | [PyPI rich 15.0.0](https://pypi.org/pypi/rich/15.0.0/json) |
| `securesystemslib-1.5.1-py3-none-any.whl` | `ada8bdf817da29ece4ba91654f6a162ce7cfbadbc3ae3f840f7313f9d22675de` | 876390 | 876390 | [PyPI securesystemslib 1.5.1](https://pypi.org/pypi/securesystemslib/1.5.1/json) |
| `sigstore-4.3.0-py3-none-any.whl` | `0f60c46c92fd4e871fbec979c9ae2aa381d7a93fbb774e49c9964550e5e16856` | 111351 | 111351 | [PyPI sigstore 4.3.0](https://pypi.org/pypi/sigstore/4.3.0/json) |
| `sigstore_models-0.0.6-py3-none-any.whl` | `5201a68f4d7d0f8bec1e2f4378eb646b084c52609a4e31db8c385095fff68b2e` | 13213 | 13213 | [PyPI sigstore-models 0.0.6](https://pypi.org/pypi/sigstore-models/0.0.6/json) |
| `sigstore_rekor_types-0.0.18-py3-none-any.whl` | `b62bf38c5b1a62bc0d7fe0ee51a0709e49311d137c7880c329882a8f4b2d1d78` | 20610 | 20610 | [PyPI sigstore-rekor-types 0.0.18](https://pypi.org/pypi/sigstore-rekor-types/0.0.18/json) |
| `tuf-7.0.1-py3-none-any.whl` | `d30434bda6e079ab303fb30d1b3006d939a10ca34783b1573d61cd9b802fa45c` | 56253 | 56253 | [PyPI tuf 7.0.1](https://pypi.org/pypi/tuf/7.0.1/json) |
| `typing_extensions-4.16.0-py3-none-any.whl` | `481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8` | 45571 | 45571 | [PyPI typing_extensions 4.16.0](https://pypi.org/pypi/typing_extensions/4.16.0/json) |
| `typing_inspection-0.4.4-py3-none-any.whl` | `65b8397ba37ccbce054456aaccddfc91e6e3083c92824df348d96ca832f3f147` | 14750 | 14750 | [PyPI typing-inspection 0.4.4](https://pypi.org/pypi/typing-inspection/0.4.4/json) |
| `urllib3-2.8.0-py3-none-any.whl` | `0cf3cae568d36aa9576b28dfb35f11328f1cb974ca7647d9475ebb86c75ac6e3` | 135717 | 135717 | [PyPI urllib3 2.8.0](https://pypi.org/pypi/urllib3/2.8.0/json) |

Audit predicates (31/31 PASS as measured in the **T5A inspection guest**): matching exact wheel filename, matching downloaded SHA-256 vs `urls[].digests.sha256`, measured length vs `urls[].size`, `yanked=false`; wheel archive path traversal and decompressed-size bounds also had no flagged results. Method: `pip download --only-binary=:all: sigstore==4.3.0`, `hashlib.sha256`/filesystem byte counts, read-only `zipfile` metadata inspection, and HTTP GET of the matching `https://pypi.org/pypi/<package>/<version>/json` release metadata. The original uncommitted machine-readable audit is retained in guest-local `pypi-crosscheck.json` under the T5A path above; **this table persists the exact name/hash/size and source-reference values for independent cross-check**. Do not infer independently authenticated provenance, signed timestamp validation, an approved loader/interpreter/root, or T5B execution permission.

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


## T5B trust-config design candidate — static T5A inspection, NOT TRUST-APPROVED

For T5B review, inspected a **separately published, test-only staging TUF repository** at immutable [`sigstore/root-signing-staging` commit `e6a4dcecdbc2c15e2c05caac5b0f0202008ef023`](https://github.com/sigstore/root-signing-staging/tree/e6a4dcecdbc2c15e2c05caac5b0f0202008ef023). This is a *candidate source distinct from the conformance bundle's repository*; it has **not** been accepted as an independent cryptographic trust anchor. Upstream explicitly says staging is for development/testing and **not suitable for production source trust**.

| Immutable candidate source file | Measured length | Measured SHA-256 |
| --- | ---: | --- |
| `metadata/root.json` | 4,221 | `3cfd686011642e1fe151d5e413524bc1fe47ac69e87d44a33a811d04fe1795b9` |
| `metadata/timestamp.json` | 450 | `a399663b1f923b15dc0b31ddc4efeece640b43c22cacf3e9f6bf3293de97b22a` |
| `metadata/snapshot.json` | 498 | `bedd2a80db1f2e0d417d98f4ce17f130290d438926aed4ce757aaca5fb4b5328` |
| `metadata/targets.json` | 4,465 | `f7b603d51b3aef6f33d515a3ce1e1c05b3fb696e1aac3eb9978751af9ed1513f` |
| `targets/trusted_root.json` | 12,722 | `44deb991d4bbf2150751ccee235d9810bce4434383c26d8898c1bcadbace6ed8` |
| `targets/signing_config.v0.2.json` | 1,215 | `7cd0090164c5c85e46d78ac44a28cca2e423967aa184c4d43c2108683ca26f62` |

**Read-only consistency result:** Both `targets/` byte counts and SHA-256s equal the respective entries in the same commit's `metadata/targets.json`. `metadata/root.json` announces root version 15, expiration `2027-03-13T01:31:42Z`; `timestamp.json` announces version 750, expiration `2026-10-22T13:26:57Z`; snapshot version 25 expires `2036-07-03T07:17:24Z`, targets version 28 expires `2036-06-29T08:21:59Z`. The presence of signed metadata and unexpired self-declared times **does not prove any TUF signatures, role threshold, rollback protection, or externally trusted clock**.

The pinned candidate `trusted_root.json` declares 5 transparency log keys, 2 CA entries, 5 CT logs and 2 TSAs. Its declared tlog IDs include the historical conformance Rekor v2 bundle's ID `8w1amZ2S5mJIQkQmPxdMuOrL/oJkvFg9MnQXmeOCXck=`, providing **static key-ID compatibility only**; Rekor inclusion, checkpoint authenticity, signature time and validity under that key **remain unverified**.

**Correct v4.3.0 config shape candidate:** `ClientTrustConfig` requires `mediaType=application/vnd.dev.sigstore.clienttrustconfig.v0.1+json`, a `trustedRoot` object and a `signingConfig` object of **media type v0.2**, not a bare `trusted_root.json`. A deterministic `json.dumps(..., sort_keys=True, separators=(",", ":")) + "\\n"` static wrapper over these two published targets was written to the **guest's candidate-only staging area**, not installed or executed: 11,700 bytes; SHA-256 `592ab025f274ce7b43376a2cd0c1085d9620c37c21c74bb84960deded8ef5390`. This is a **locally assembled, unauthenticated candidate configuration**, and is **not included as a trusted executable policy**. Do not pass it to `sigstore verify` until all T5B checks and exact material execution consent are complete.

**Still missing T5B:** independently authenticated TUF root bootstrap and signature thresholds/metadata chain; externally trusted offline wall clock/skew and numerical freshness/rollback limits (including older 2025 signed test fixture); correct TSA/certificate SCT/CT/log inclusion cryptography and revocation policy; complete 31-wheel interpreter/native-loader/environment provenance, version-compatible parser behavior, precisely specified network-denied sandbox and one approved sealed-digest/FD handoff. Self-consistent staging metadata cannot approve itself. No genuine Sigstore verification was run; `SYNTHETIC_ONLY` GREEN/hostile RED remain **NOT EXECUTED**. Real macOS `.pkg`, B0b, UID502/APFS and production source acceptance remain out of scope.


## 2026-10-16 T5 conditional cryptographic TUF audit (bootstrap NOT independently trusted)

**Scope:** independent, non-privileged **research-only** signature checks using the disposable Linux x86_64 Python 3.14.4 guest and the guest's existing `/usr/bin/openssl`; no external Sigstore 4.3.0 verifier or any candidate wheel was imported, installed, or executed, no operator-root selection/privilege/network-at-verification permission was conferred. Published staging TUF metadata was **retrieved read-only** from exact Git commit `sigstore/root-signing-staging@e6a4dcecdbc2c15e2c05caac5b0f0202008ef023` (file SHA-256s above). This does not authenticate that Git source or its self-supplied root public keys independently.

**Important TUF canonicalization discovery:** TUF signatures use [securesystemslib canonical JSON](https://docs.rs/sigstore-tuf/latest/sigstore_tuf/canonical_json/index.html), **not** Python's normal `json.dumps(sort_keys=True, separators=(',', ':'))`: notably, control characters such as literal newlines inside PEM public key fields are emitted as **raw UTF-8**, unlike JSON's usual `\\n` escaping. The initial ordinary-JSON check produced `0/2` Root signatures and was **invalid methodology**; the corrected TUF-canonical signed-body bytes were checked using `openssl dgst -sha256 -verify <role-pubkey> -signature <DER-ecdsa-signature> <canonical-signed-bytes>`. Each role key and threshold were taken from the **same candidate root**; distinct valid signer key IDs were counted. Conditional cryptographic results:

| Staging role | Valid role signatures / candidate root threshold | Signed version | Cryptographic check under *self-supplied* keys |
| --- | ---: | ---: | --- |
| Root | 2 / 2 | 15 | **PASS, conditional only** |
| Timestamp | 1 / 1 | 750 | **PASS, conditional only** |
| Snapshot | 1 / 1 | 25 | **PASS, conditional only** |
| Targets | 2 / 1 | 28 | **PASS, conditional only** |

Timestamp's declared `snapshot.json` version agrees with snapshot v25; snapshot's declared `targets.json` version agrees with targets v28. The candidate `targets.json` SHA-256 **and byte lengths** of `trusted_root.json` and `signing_config.v0.2.json` match the measured exact bytes recorded above. **Not tested:** independently anchored Root v1→v15 rotation; previous trusted version/rollback prevention; independent trusted clock, timestamp-v750 repository freshness or offline root revocation; independently pinned Sigstore interpreter/native loader and all 31 dependency origins. [Sigstore staging repository documentation](https://github.com/sigstore/root-signing-staging) expressly says this staging trust domain is **not appropriate for production**. Conditional signature validity is **NOT independent T5B trust authorization**.

**Archival signed-time inspection, also research-only:** the official archived conformance `rekor2-happy-path` bundle provides a DER certificate whose unauthenticated `openssl x509 -text` fields claim `NotBefore=2025-06-12 12:02:16 UTC`, `NotAfter=2025-06-12 12:12:16 UTC`, `Issuer=O=sigstore.dev, CN=sigstore-intermediate`, workflow SAN `https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main`, OIDC issuer `https://token.actions.githubusercontent.com`. Extracted bundle `timestampVerificationData.rfc3161Timestamps[0].signedTimestamp` has SHA-256 `2ece34826c62901de084dd0b39850ee7500f283adf303c05615ae8dcf8dcaef5`; using `OPENSSL_CONF=/dev/null openssl ts -reply -in <DER-response-file> -text` reports `Status: Granted`, claimed **Time stamp: 2025-06-12 12:02:20 UTC**, within the **claimed** 10-minute certificate window. **Neither** the RFC3161 TSA signature nor Fulcio chain, SCT, Rekor inclusion/checkpoint or OIDC have yet been cryptographically validated; there is no authenticated historical time or accepted 2026 revocation disposition, and no genuine signature GREEN/RED.

**Required independent T5 decision remains a HARD STOP:** separately authenticated TUF bootstrap root/history/rollback, approved exact 31-wheel/interpreter/loader/transitive binary closure (local hashes ≠ build provenance), accepted full `ClientTrustConfig` from authenticated sources, validated signer/cert/log/TSA signed time and numerical 2026 clock/skew/staleness/revocation policy explicitly handling the expired June 2025 sample, one approved `digest-from-registered-sealed-bytes` or direct sealed-FD handoff, and separate permission to execute **that exact approved pinned** Sigstore 4.3.0 tool in network-denied credential-free Linux. No `SYNTHETIC_ONLY` result may be emitted from this read-only research.

**Integration/independent review gate:** the user requested “Gate I”; no separate formally named `Gate I` was found in the checked-in B0a design/plan. The applicable feature's Task 5 / final integration acceptance remains exact-HEAD hosted CI and independent whole-project security review **after** real pinned-tool T5 GREEN plus hostile RED. Prior CI green on the refusal-only/static-tests code does not close final integration or permit GitHub `Ready for Review`. Real macOS `.pkg`, B0b, UID502/APFS, production package source/release and merging remain explicitly excluded.


### Conditional historical TUF root-rotation chain (research-only)

From the **same fixed upstream staging Git commit** `e6a4dcecdbc2c15e2c05caac5b0f0202008ef023`, also fetched the 15 historical `metadata/root_history/{1..15}.root.json` records and checked their signed `version` fields. On each step, using corrected securesystemslib-style TUF canonical JSON and existing `/usr/bin/openssl dgst -sha256` ECDSA checks, required **both** the *previous Root role's* signature threshold **and** the *new Root role's* signature threshold over the next root's signed bytes. **Conditional results: 1/1 initial Root self-signature PASS; all 14 transitions (v1→v2 through v14→v15) passed both old-key and new-key role thresholds; current `metadata/root.json` signed body equals the historical v15 signed body.** In transition v6, root threshold increased from 1 to 2; both threshold checks passed. This reduces *internal* history-consistency uncertainty, but **DOES NOT authenticate the v1 bootstrap**: v1 and all later root material were downloaded from the same untrusted upstream repository, and no independently reviewed initial-root digest/key fingerprint, minimum previously trusted version or actual rollback state was supplied. The operator must first independently approve a specific initial trust anchor and checkpoint/version before this chain can have T5B authority. Do not mark T5B or a Sigstore signed-fixture GREEN based on these conditional checks.

## 2026-10-16 independent leaf-signature arithmetic preflight (conditional, NOT T5B)

**Scope:** read-only verification of the already pinned, archived, **UNAPPROVED** Sigstore conformance `rekor2-happy-path` fixture, not invocation of Sigstore 4.3.0 and not trusted certification. Run on ordinary Yuz.local Python 3.13.5 with installed `cryptography 45.0.5` against the exact repository fixture bytes; no external binary/roots were installed or invoked, no network access and no privileged host actions. This is an additional **T5A conditional cryptographic observation** under a **bundle-supplied, untrusted leaf public key**, not genuine T5B verifier GREEN.

- Original 109-byte `sigstore-conformance-a.txt` SHA-256 `a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf`; unchanged v0.3 Rekor2 bundle 10,123 bytes SHA-256 `3a5ce62cee2653969be846a41e8332eae82c633cdfafe6db48b10e60939518dd`. The bundle-declared SHA-256 matches the separately measured bytes.
- Decoded bundle `messageSignature.signature` is a 72-byte DER ECDSA signature (SHA-256 `6ddf31609e2a6c814f8266aab75204b7a1f5e96d1bc07dde6ff39add8408cda2`). Decoded leaf DER certificate SHA-256 `bb2b81c4f07d282f71e99007e78584dbf7b086793fabfdde7c45244a946ac639`; its **own untrusted** EC public key verified that signature over the **original full artifact bytes** using `ec.ECDSA(hashes.SHA256())`: **PASS**.
- Keeping the original signature, cert and bundle unchanged, changing **only the first artifact byte** (`bytes([payload[0] ^ 1]) + payload[1:]`, same 109-byte length) failed `verify()` with `InvalidSignature`: **expected negative PASS**. The same signature did **not** verify over binary SHA-256 digest or its hex text; the matched signature message was the raw original artifact bytes.
- Reproduction: load `bundle["verificationMaterial"]["certificate"]["rawBytes"]` using `x509.load_der_x509_certificate(base64.b64decode(...))`; load `bundle["messageSignature"]["signature"]` as base64, then call `certificate.public_key().verify(signature, payload, ec.ECDSA(hashes.SHA256()))` for the original and one-byte-modified `payload`. Compare the pinned fixture SHA-256s before any test. No certificate chain or authenticity assertion follows from this call.

**Boundary remains:** the leaf certificate, public key, claimed identity and original signature are all from the **same untrusted bundle**. This test has **NOT** established an independently trusted Fulcio root/chain, CT/SCT, approved SAN/OIDC, Rekor2 log/checkpoint/inclusion, RFC3161 TSA signature and signed-time chain, historical revocation, TUF bootstrap/rollback, exact Sigstore 4.3.0 runtime or operator T5B execution approval. A mathematically valid signature under an untrusted leaf key is **not** signer identity/provenance authentication, not an approved signed test fixture, and not the actual pinned offline Sigstore verification. **Keep PR #268 Draft; no `SYNTHETIC_ONLY` claim, no T5B/Gate I acceptance.**

## 2026-10-16 conditional RFC3161 embedded-CMS signature and imprint check (NOT trusted time)

**Additional non-authorizing T5A arithmetic evidence:** using installed Yuz.local OpenSSL **3.0.17** on the same archived bundle only (no Sigstore verifier, tool installation, extra key/root acquisition, network or privilege), base64-decoded the bundle RFC3161 `signedTimestamp` response (SHA-256 `2ece34826c62901de084dd0b39850ee7500f283adf303c05615ae8dcf8dcaef5`). `openssl ts -reply -in response.der -token_out -out token.der` succeeded; `openssl cms -verify -inform DER -in token.der -noverify -out content.der` returned **0**, validating the **CMS cryptographic signature under its embedded, UNTRUSTED certificate** without validating any TSA trust chain. This is not equivalent to `openssl ts -verify` with independently authenticated TSA trust and signed-data policy.

A separate `openssl ts -reply -in response.der -text` parsed `Hash Algorithm: sha256`, the 32-byte `Message data: 6d df 31 60 9e 2a 6c 81 4f 82 66 aa b7 52 04 b7 a1 f5 e9 6d 1b c0 7d de 6f f3 9a dd 84 08 cd a2`, and a claimed timestamp `2025-06-12 12:02:20 UTC`. The imprint is **exactly SHA-256 of the archived artifact's 72-byte ECDSA signature**, independently computed as `6ddf31609e2a6c814f8266aab75204b7a1f5e96d1bc07dde6ff39add8408cda2`. The claimed time falls between the same bundle leaf certificate's **claimed** `2025-06-12 12:02:16 UTC` and `12:12:16 UTC` bounds. The mathematical CMS signature and imprint agreement do not authenticate the TSA certificate, timestamp authenticity under a separately pinned root, CT/Fulcio/Rekor, historical certificate revocation or 2026 freshness; a self-supplied cert and time source cannot independently establish trust.

**T5B remains BLOCKED:** independently approved TSA chain and time/revocation policy, Fulcio/OIDC/CT/Rekor inclusion/checkpoint, TUF bootstrap/anti-rollback, pinned Sigstore toolchain and precise sealed-byte handoff plus operator execution authorization are still absent. No `SYNTHETIC_ONLY`, no complete signed verifier GREEN/RED, no Ready/merge.

### 2026-10-16 conditional Rekor2 Merkle inclusion + checkpoint signature audit (T5A ONLY)

**Scope:** Read-only, independently recomputed **mathematical consistency** of the exact already-admitted 10,123-byte archived Sigstore conformance bundle and 109-byte artifact on Yuz.local with installed Python 3.14.8 stdlib and OpenSSL 4.0.3. No Sigstore candidate verifier installation/import/execution, new root installation, real package, networking or privilege. Candidate Ed25519 key from **unapproved** `sigstore/root-signing-staging@e6a4dcecdbc2c15e2c05caac5b0f0202008ef023` `targets/trusted_root.json`, historical log `log2025-alpha1.rekor.sigstage.dev` (`keyId=8w1amZ2S5mJIQkQmPxdMuOrL/oJkvFg9MnQXmeOCXck=`), which was previously measured statically. **Neither the key nor log identity is independently authenticated.**

1. Decode `verificationMaterial.tlogEntries[0].canonicalizedBody`. Its `hashedRekordV002.data.digest` **equals SHA-256 of all 109 artifact bytes**. Its `signature.content` and `signature.verifier.x509Certificate.rawBytes` equal the outer bundle's `messageSignature.signature` and `verificationMaterial.certificate.rawBytes` **byte-for-byte**.
2. Independently calculate RFC6962 Merkle leaf `SHA256(0x00 || canonicalizedBody)`, fold **eight** inclusion hashes with internal-node prefix `0x01`, at `logIndex=735` / `treeSize=736`. Calculated root **`aecd583d8d3274057497181faeae69138a11a54270a37b327a9b39f9e1944c32`** equals decoded `inclusionProof.rootHash`. A modified canonicalized body yields a different computed root: **expected RED**. The checkpoint note reports the same tree size and root.
3. Decode the signed checkpoint note: origin `log2025-alpha1.rekor.sigstage.dev`, size `736`, root above, then a 68-byte signature (4-byte signed-note key hint + 64-byte Ed25519 signature). With OpenSSL `pkeyutl -verify -rawin`, verify the 64-byte signature against **the exact three-line checkpoint text including one final newline, excluding the separating blank line**, using the **candidate-only** staging TUF DER/SPKI public key `MCowBQYDK2VwAyEAPn+AREHoBaZ7wgS1zBqpxmLSGnyhxXj4lFxSdWVB8o8=`: **PASS**. Change only the checkpoint's signed root text while retaining the original signature: **expected RED**. The bundle log ID equals the candidate TUF record's *declared* log ID; **do not claim it equals SHA-256 of the DER public key** (it does not).
4. Historical candidate log key `validFor` **2025-04-16 through 2025-09-04** spans the archived TSA's *claimed* June 12, 2025 time. This is internal date compatibility only, **not** authenticated log time or historical revocation.

**Boundary:** Inclusion math and Ed25519 checkpoint-note signature hold **only under a self-published unauthenticated staging key**. No independent Rekor log/key authenticity or checkpoint custody, independently trusted TUF bootstrap, TSA/Fulcio/CT/OIDC/revocation, or actual pinned Sigstore verifier GREEN was established. This is **not** Gate T5B, **not** `SYNTHETIC_ONLY`, and does not authorize real macOS packages or Ready/merge. Require independent approved T5B policy, genuine pinned-tool test-key GREEN plus hostile RED, final exact-head CI and full-feature review.

### 2026-10-16 conditional Fulcio chain and complete RFC3161 TSA verification against staging candidates (T5A ONLY)

**Scope:** Reuse the immutable, **unapproved** staging TUF target `trusted_root.json` (staging repository commit `e6a4dcecdbc2c15e2c05caac5b0f0202008ef023`, target length 12,722, SHA-256 `44deb991d4bbf2150751ccee235d9810bce4434383c26d8898c1bcadbace6ed8`) as **candidate input data** for local installed OpenSSL 4.0.3 in a disposable temp directory. This tests mathematical chain consistency only. No Sigstore verifier install/import/invocation, trust-root installation, externally authenticated signer approval, or real macOS artifact use. All apparent roots and chains were provided by the **same unauthenticated staging TUF target**.

- Extract `certificateAuthorities[0].certChain.certificates`: element 0 is intermediate `O=sigstore.dev, CN=sigstore-intermediate` (issuer `CN=sigstore`), element 1 is candidate self-signed `CN=sigstore` root. The archived conformance bundle leaf's issuer is `sigstore-intermediate`. Using candidate CA element **1** as `-CAfile` and element **0** as `-untrusted`, `openssl verify -no-CAfile -no-CApath -no-CAstore -CAfile ca1.pem -untrusted ca0.pem -attime <2025-06-12T12:02:20Z Unix seconds> -purpose any leaf.pem` returned **0 / OK**. Reversing the trust anchor and intermediate failed `unable to get issuer certificate`. This proves **claimed 2025-era certificate-chain consistency only under the untrusted candidate Fulcio root**, not independent provenance.
- Extract `timestampAuthorities[0].certChain.certificates`: element 0 `CN=sigstore-tsa` issued by element 1 `CN=sigstore-tsa-selfsigned`. Decode the archived RFC3161 response and original ECDSA signature. `openssl ts -verify -in resp.der -data signature.bin -CAfile tsa1.pem -untrusted tsa0.pem` returned **`Verification: OK`, exit 0**: CMS TSA signature chain and RFC3161 imprint checked **conditional on that candidate TSA root**. Modifying only the first byte of `signature.bin` with the original timestamp response gave **`Verification: FAILED` / `message imprint mismatch` (expected RED)**. Reversing candidate root/intermediate roles failed `self-signed certificate in certificate chain` (expected refusal). OpenSSL also warned the supplied TSA leaf in `-untrusted` is not a CA certificate; the correct-chain/original-data check still returned success, and no warning was suppressed.
- This adds conditional chain/TSA crypto checks to the earlier untrusted-leaf ECDSA, RFC6962 Rekor inclusion, and Ed25519 checkpoint math. It does **not** authenticate upstream TUF bootstrap, trusted historical clock, SCT/CT, approved SAN/OIDC identity/role, Rekor log key custody, anti-rollback, historical revocation, or numeric freshness/skew. Passing a chain rooted in the same source's own candidate root is **not** an independent trust decision.

**Final gate:** **T5B stays UNRESOLVED**. No fully independently attested Sigstore 4.3.0 toolchain/31-wheel/loader or end-to-end pinned-verifier signed GREEN+paired hostile RED. No `SYNTHETIC_ONLY`, PR Ready/formal review/merge, real installer/B0b/UID502.

## 2026-10-16 candidate verifier loader/native-extension static closure (T5A, NOT APPROVED)

**Read-only research on the existing Lima Ubuntu 26.04 Linux x86_64 guest** (`ssh-over-mcp-cgroup-live-x86`); no candidate Sigstore wheel imported/installed/executed, no runtime, root or library installed, and no disposable T5B execution sandbox prepared. Existing guest state is *not* a reviewed fresh disposable verification runtime. Hashes below bind inspected bytes **only on that guest at this instant**; package-manager metadata, Python runtime and loader remain **UNAUTHENTICATED**.

The previously T5A-downloaded **31/31** wheel files passed another fresh `sha256sum -c /tmp/som-pr268-t5a-candidates-20261015/manifest.sha256` check. The exact wheel hash/lengths are preserved in the earlier 31-row evidence table above. The raw manifest file SHA-256 is `299d5a999dc0cc65f3372f811463bf56e88e5a7d85ac8467bf0697d1e2e1fe59`.

The candidate guest system interpreter is `/usr/bin/python3` → `/usr/bin/python3.14`; both resolve to byte-identical SHA-256 `52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41`, reported version Python 3.14.4. `readelf -l /usr/bin/python3.14` reports ELF interpreter `/lib64/ld-linux-x86-64.so.2`. Read-only `ldd` reports these *direct interpreter* dynamic libraries, each independently hashed from installed disk bytes:

| ELF candidate object | SHA-256 (guest-only, NOT authenticated) |
| --- | --- |
| `/lib64/ld-linux-x86-64.so.2` | `bda779ea9e9ad234f60315477d7cfd0bdde861cd8ddd9df8cdaf62f18c4cec14` |
| `/usr/lib/x86_64-linux-gnu/libm.so.6` | `1c488db6f4fe8cecb72456bc018de000b7a9b539c2994864b0416b5e8371b3d8` |
| `/usr/lib/x86_64-linux-gnu/libz.so.1` | `47b61967895b30e8c0c6818dd633ffeb87711cf637c688f981896f0dd84ce23b` |
| `/usr/lib/x86_64-linux-gnu/libexpat.so.1` | `2e5f66e2784c2746775567ff9916f6e7503182a8f1f2deb8ca729dfc1463849f` |
| `/usr/lib/x86_64-linux-gnu/libc.so.6` | `85e64f97e348786a8fb4d9f3d52fec289e2fb86bba20f0731dfe61990525e0f7` |

Read-only Python `zipfile` inspection of the **31 still-uninstalled wheel archives** enumerated **6** native ELF extension entries (SHA-256 of the decompressed archive member bytes):

| Wheel member (candidate-only) | SHA-256 |
| --- | --- |
| `_cffi_backend.cpython-314-x86_64-linux-gnu.so` (in `cffi-2.1.1` wheel) | `7d1eff7fbb874ee72228fd426103da2b9eef528979156077bdec736d5b4f61a2` |
| `charset_normalizer/cd.cpython-314-x86_64-linux-gnu.so` | `4ca0b03cc9e0d6a206c33433c2d62fbd43dc0eca43015c8532635ee66ea60818` |
| `charset_normalizer/md.cpython-314-x86_64-linux-gnu.so` | `a92bc8c547c9fdc8b6f1d4d20a6500bdaf3622893202b206ce7b6c516a5f8be9` |
| `cryptography/hazmat/bindings/_rust.abi3.so` | `0629ac2efafdf1eecd9f14fdbf5efb205b0431af08964ba78484a972396ce859` |
| `pydantic_core/_pydantic_core.cpython-314-x86_64-linux-gnu.so` | `f1c6034d9d708521893241e1f597532aab8c334fddc10b8773f6a73e0503577b` |
| `rfc3161_client/_rust.abi3.so` | `cec5ada79a8754fbbf000fec318f8d54bc902029ea65cc31e720840a01930cf3` |

**Do not treat this as a complete trusted loader/OS closure.** There are at least **49** installed CPython stdlib `lib-dynload/*.so` candidate files on that guest not individually admitted, and no dynamic dependency inventory for the six uninstalled wheel ELF members, no interpreter build/Ubuntu image/signed apt provenance, no verified `DT_NEEDED` transitive graph, no closure after environment isolation or root/TUF authenticity. A fresh, controlled, independently attested immutable verifier runtime is **still required** for Task 0/T5B; no candidate was made executable or installed from this inspection. No operator/security approval of these digests is inferred. Do not mark PR Ready or report actual Sigstore signature GREEN/RED from this evidence.
