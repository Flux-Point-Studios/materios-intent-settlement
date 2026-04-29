# Security Policy

## Reporting a Vulnerability

If you discover a security issue in `materios-intent-settlement`, please report
it privately rather than via a public GitHub issue.

**Preferred channels:**

1. **GitHub Security Advisory** (private):
   <https://github.com/Flux-Point-Studios/materios-intent-settlement/security/advisories/new>
2. **Email:** `security@fluxpointstudios.com`

Please include:

- A clear description of the issue and its impact
- Steps to reproduce, ideally with a minimal proof-of-concept
- The component(s) affected (pallet / SDK / keeper / e2e)
- Your name or handle if you'd like to be credited

We aim to acknowledge reports within **3 business days** and to provide a
remediation plan within **10 business days**. Critical issues affecting
deployed mainnet contracts will be triaged on an accelerated timeline.

Standard disclosure window is **90 days** from initial report. We may request
an extension for complex issues; we'll communicate that proactively.

## Scope

This policy covers:

- `pallets/intent-settlement` (FRAME pallet)
- `pallets/committee-governance` (FRAME pallet)
- `keeper/` (off-chain TypeScript relayer)
- `sdk/` (client SDK)
- `e2e/` (integration test harness — only insofar as it ships example code
  that consumers may copy)

The Aiken validators referenced by this repo live in a sister repository
(`aegis-parametric-insurance-dev`) and are governed by that repository's own
security policy.

## Status

This codebase has **not yet been independently audited**. The most recent
internal security review was conducted on **2026-04-28** as part of pre-
open-source readiness. A summary of known limitations is in `README.md` under
the **Status** section.

Until a formal external audit lands, the project is considered **alpha** and
should not be used to settle real funds on Cardano mainnet. Preprod use is
fine; integrators are encouraged to read the Status section before building
on top of this primitive.

## Cryptographic surfaces

The pallet and SDK use:

- `sr25519` for Materios committee signatures (FRAME signer scheme)
- `ed25519` on the Aiken validator side (committee mirror set)
- `blake2_256` for domain-separated digest construction
- `blake2b_224` for Plutus V3 script-hash verification (keeper-side)

Domain separation is enforced via 4-byte tags (`CRDP`, `STCL`, `RVCH`, `STBA`,
`ABIN`, `RVBN`, `SBIN`, `INTA`, `VCHR`). Reports of cross-tag confusion or
missing chain-identity binding are explicitly in scope.

## Out of scope

- Vulnerabilities in upstream dependencies that are already disclosed and
  tracked publicly. (We carry advisories for `ip`, `vite`, `esbuild`,
  `elliptic`, and the Rust `time` crate; see the project's `pnpm audit` and
  `cargo audit` output.)
- Vulnerabilities affecting only the example demos under `e2e/scripts/` that
  cannot be reproduced against the pallet, SDK, or keeper themselves.
- Issues that require physical access to a validator host or operator's
  signing-key material.

## Hall of Fame

Disclosed issues will be credited here once a remediation has shipped, unless
the reporter prefers anonymity.

_(none yet — this repo is pre-public-release as of 2026-04-28.)_
