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

Users can step through the original Needham-Schroeder flow, watch the Lowe attack succeed against it, then apply Lowe's fix and watch **the same relay re-run against the patched protocol** — Mallory is still on the wire, Bob still answers, and Alice aborts at message 2 on the identity mismatch. From there, run the full Kerberos v5 AS/TGS/AP flow with real AES-256-CTS-HMAC-SHA1 encrypted tickets, pre-authentication, and a replay button that re-submits the captured AP-REQ bytes verbatim. The clock can be skewed live to watch replay and expiration defenses fire.

The lab is built as a clickable historical timeline where each era exists because the previous one broke: attack found → one-line fix → redesign. Teaching aids layered on top for a first-time reader:

1. **Timeline + message flow** — pick an era (Needham-Schroeder 1978, Lowe attack 1995, Lowe fix, Kerberos v5) and watch its swimlane play out message by message.
2. **Lowe re-seal capsule** — when Mallory relays a message, an on-screen capsule shows the outer public-key envelope changing (`_pkM` → `_pkB`) while the sealed inner secret stays untouched, making "relay without decrypting" visible.
3. **Crypto-changed signpost** — an anchored banner fires the moment you enter the Kerberos scenario, naming the shift from per-party public keys to a trusted KDC with symmetric session keys.
4. **Three-exchange orientation card** — a "why three round-trips" primer (AS / TGS / AP) shown before the six-message flow, so the complexity is sequenced, not dumped.
5. **Grouped threat model** — the attack outcomes are grouped by the defense that stops them (replay / clock skew / ticket expiry / key theft / the pre-Kerberos flaw), each an expandable card with "what an attacker tries" vs "what stops them", and hoverable definitions for terms like Kerberoasting, pass-the-ticket, and AS-REP roasting.
6. **Self-teaching clock slider** — the ±5-minute tolerance is marked on the track with a live "within tolerance / SKEW" badge, so the skew defense is discoverable by dragging rather than only after a failure.
7. **In-app scope panel** — an on-screen statement of what the demo models faithfully, what it deliberately omits (ASN.1/DER, cross-realm, the PAC), and where exactness is compressed, so the limits are visible without reading the source.

Every outcome shown is computed live in the browser against the real cryptography; none of the teaching layer fakes a result. Concretely, that means:

- The **Lowe fix** scenario runs Mallory's relay against the fixed protocol and reports whether Alice aborted — it is not an attacker-free run relabelled as a defense.
- **Replay last AP-REQ** re-submits the captured authenticator ciphertext to the service, which decrypts it and verifies its HMAC-SHA1-96 before refusing it on freshness. It is not a cache lookup.
- The **ticket-expiry** card is fed a genuinely expired ticket, and **AS-REP roasting** is demonstrated by issuing an AS-REP for a pre-auth-disabled account and cracking its `enc-part` from a dictionary in the browser — every pass/fail glyph in the threat panel comes from a value one of these runs returned.
- **Pre-authentication** (PA-ENC-TIMESTAMP, key usage 1) is implemented and verified by the KDC, so the `pre-authent` ticket flag in the inspector is earned rather than decorative — and the roastable account is the exhibit for what happens without it.

## Scope and Limitations

The same statement is shown in the app itself, in the **What this demo is, and is not** panel.

- **The cryptography is real; the encoding is not.** aes256-cts-hmac-sha1-96, the RFC 3961 DK/DR derivation, PBKDF2 × 4096, and the RFC 4120 key usage numbers are implemented as specified. But ticket bodies, authenticators, and everything shown under "Raw bytes" are **JSON** that is then encrypted — RFC 4120 puts ASN.1/DER on the wire.
- **One realm.** No cross-realm referrals, no inter-realm krbtgt, no trust hierarchy.
- **No PAC.** The Active Directory authorization-data blob and its signatures are absent, so nothing here shows how Kerberos carries authorization rather than authentication.
- **Pre-authentication is PA-ENC-TIMESTAMP only.** No PKINIT, no FAST armoring, no hardware or OTP pre-auth types. The AS exchange is modelled on the KDC clock, so the clock slider demonstrates skew at the AP exchange; a real KDC would also reject a skewed AS-REQ with `KDC_ERR_PREAUTH_FAILED`.
- **No network, no ccache.** No port 88, no DNS SRV discovery, no on-disk credential cache — the `klist -e` inspector is a rendering. One etype (18), one kvno, no negotiation or key rotation.
- The 1978/1995 scenarios use **RSA-OAEP** because that is what the browser offers; Needham-Schroeder predates OAEP, and the relay property the attack turns on is unaffected by the padding.

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
- **Protocol behaviour** — the Lowe attack succeeds against Needham-Schroeder
  and the *same relay* is blocked by the one-line fix (both directions are
  asserted, so the test fails if either regresses); a captured AP-REQ
  re-submitted byte-for-byte still decrypts and HMAC-verifies but is refused on
  freshness; pre-authentication gates the AS-REP and the `pre-authent` flag; and
  the Kerberos clock-skew / replay / expiry defenses each fire
  (`test/protocols.test.ts`).

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

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
