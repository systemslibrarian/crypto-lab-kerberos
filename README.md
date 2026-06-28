# crypto-lab-kerberos

## What It Is

Kerberos (RFC 4120) is a trusted-third-party authentication protocol descended from MIT's 1988 Athena project. This demo walks the 47-year arc: Needham-Schroeder (1978) -> the Lowe attack (1995) -> Kerberos v5 with AES-256-CTS-HMAC-SHA1 (RFC 3962). The security model assumes a trusted Key Distribution Center (KDC) and synchronized clocks across all principals.

## When to Use It

- Enterprise single sign-on with a central identity authority - what Active Directory and FreeIPA actually run on.
- Environments where every client can reach the KDC but not every service can reach every identity provider - the TGT caches authenticated sessions.
- Cross-realm trust with explicit delegation - a structured answer to the "one federation to rule them all" problem.
- Do NOT use Kerberos when clients can't sync to within 5 minutes of the KDC - skew failures are unforgiving.
- Do NOT use Kerberos-only for internet-scale authentication - token-based protocols (OIDC, OAuth) compose better with HTTP.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-kerberos](https://systemslibrarian.github.io/crypto-lab-kerberos/)**

Users can step through the original Needham-Schroeder flow, watch the Lowe attack succeed against it, apply Lowe's fix and watch the attack fail, then run the full Kerberos v5 AS/TGS/AP flow with real AES-256-CTS-HMAC-SHA1 encrypted tickets. The clock can be skewed live to watch replay and expiration defenses fire.

## What Can Go Wrong

- **Clock skew** - if a client drifts beyond the KDC's tolerance (commonly around 5 minutes), authentication fails outright because timestamps anchor the replay and expiry defenses.
- **KDC compromise** - the KDC is a single point of trust; theft of the krbtgt key lets an attacker mint arbitrary tickets ("golden ticket") for any principal.
- **Replay without a working replay cache** - captured authenticators can be replayed within their lifetime if the service does not retain and check them.
- **Weak principal passwords** - service and account keys derived from weak passwords are exposed to offline cracking of pre-auth data and service tickets (Kerberoasting-style attacks).
- **Ticket theft** - possession of a ticket is sufficient to use it; stolen ticket material can be reused (pass-the-ticket) until it expires.

## Real-World Usage

- **Microsoft Active Directory** uses Kerberos v5 as its primary domain authentication protocol.
- **MIT Kerberos** and **Heimdal** are the reference open-source implementations.
- **FreeIPA / Red Hat IdM** builds enterprise identity management on a Kerberos KDC.
- **Hadoop, NFSv4, and other services** authenticate via Kerberos through GSSAPI/SPNEGO.
- **Standards** - RFC 4120 specifies Kerberos v5; RFC 3962 adds the AES-CTS-HMAC-SHA1 encryption types used here.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-kerberos
cd crypto-lab-kerberos
npm install
npm run dev
```

## Related Demos

- [crypto-lab-pki-chain](https://systemslibrarian.github.io/crypto-lab-pki-chain/) — X.509 certificate trust, the other pillar of enterprise authentication.
- [crypto-lab-webauthn](https://systemslibrarian.github.io/crypto-lab-webauthn/) — FIDO2 passkeys, the token-based path Kerberos does not cover.
- [crypto-lab-ssh-handshake](https://systemslibrarian.github.io/crypto-lab-ssh-handshake/) — host authentication and key exchange over SSH.
- [crypto-lab-opaque-gate](https://systemslibrarian.github.io/crypto-lab-opaque-gate/) — password-authenticated key exchange without a trusted KDC.
- [crypto-lab-web-of-trust](https://systemslibrarian.github.io/crypto-lab-web-of-trust/) — decentralized trust as a contrast to Kerberos's central authority.

## Why You Can Trust the Crypto

The cryptography is not a simulation, and it is not merely self-consistent — it
is validated against the **published RFC known-answer vectors**:

- **n-fold** — every vector in RFC 3961 §A.1 (`test/nfold.test.ts`).
- **string-to-key** (PBKDF2 → n-fold → DR/DK) — the RFC 3962 §B sample
  vectors, including the high-iteration, block-size-boundary, and non-ASCII
  (g-clef) cases (`test/string2key.test.ts`).
- **PBKDF2-HMAC-SHA1** — cross-checked against Node's OpenSSL-backed
  implementation, an entirely independent code path.
- **AES-256 block cipher** — the FIPS-197 known-answer vector (`test/cts.test.ts`).
- **Protocol behaviour** — the Lowe attack succeeds against Needham-Schroeder,
  the one-line fix blocks it, and the Kerberos clock-skew / replay / expiry
  defenses each fire (`test/protocols.test.ts`).

The same RFC 3962 §B string-to-key vector also runs live in the browser on every
page load (the **Self-check** panel), so visitors can watch the in-browser
derivation reproduce the published key. CI (`.github/workflows/ci.yml`) runs the
type-checker and the full suite on every push; deploys are gated on it.

You can run the same checks locally:

```bash
npm run check    # type-check + full test suite
```

## Landing Page Card

- Category: Authentication Protocols
- Chips: Kerberos (RFC 4120) · Needham-Schroeder · Lowe Attack · AES-CTS-HMAC-SHA1
- One-line description: "The 47-year arc from Needham-Schroeder 1978 through the Lowe attack 1995 to Kerberos v5 - real AES-256-CTS-HMAC-SHA1 tickets, replay cache, clock skew, and the protocol Active Directory still runs on."

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
