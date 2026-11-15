# crypto-lab-kerberos

## What It Is

Kerberos (RFC 4120) is a trusted-third-party authentication protocol developed at MIT's Project Athena (announced in May 1983) and first published in 1988 (Steiner, Neuman and Schiller, USENIX Winter 1988). This demo walks two lineages that share one 1978 paper. The first is the public-key Needham-Schroeder protocol (1978), Lowe's attack on it and the one-line fix (1995). The second is Kerberos v5 with AES-256-CTS-HMAC-SHA1 (RFC 3962), which descends from the same paper's shared-key protocol via the Denning-Sacco timestamp modification (RFC 4120 §1) — specified in RFC 1510 (September 1993), two years before Lowe's attack, and superseded by RFC 4120 (July 2005). The security model assumes a trusted Key Distribution Center (KDC) and synchronized clocks across all principals.

**Standards/history reviewed 15 November 2026:** this README, the in-app timeline rail, the hero and the threat-panel group heading previously presented a single "47-year arc: Needham-Schroeder (1978) → the Lowe attack (1995) → Kerberos v5" in which "each era exists because the previous one broke". That was wrong in three ways. Kerberos v5 predates Lowe's attack: [RFC 1510](https://www.rfc-editor.org/info/rfc1510) is dated September 1993, and Lowe's paper is "An attack on the Needham-Schroeder public-key authentication protocol", Information Processing Letters 56(3), November 1995 ([doi:10.1016/0020-0190(95)00144-2](https://doi.org/10.1016/0020-0190(95)00144-2)). Lowe's attack is on the *public-key* Needham-Schroeder protocol — his title says so — whereas [RFC 4120 §1](https://www.rfc-editor.org/rfc/rfc4120.html#section-1) says "The Kerberos model is based in part on Needham and Schroeder's trusted third-party authentication protocol [NS78] and on modifications suggested by Denning and Sacco [DS81]", and §1.1 that Kerberos authenticates "by using conventional (shared secret key) cryptography". So the attack that shaped Kerberos is Denning and Sacco's — "Timestamps in Key Distribution Protocols", Communications of the ACM 24(8), August 1981 ([doi:10.1145/358722.358740](https://doi.org/10.1145/358722.358740)), whose abstract shows "that key distribution protocols with timestamps prevent replays of compromised keys" — and it was missing, while Lowe's, which did not shape Kerberos, stood in its place. Needham and Schroeder's paper is "Using Encryption for Authentication in Large Networks of Computers", Communications of the ACM 21(12), December 1978 ([doi:10.1145/359657.359659](https://doi.org/10.1145/359657.359659)); its abstract notes that "Both conventional and public-key encryption algorithms are considered as the basis for protocols." The four runnable eras are unchanged; every claim that one led to the next has been removed, and the Kerberos entry now carries its own lineage and dates. The same paragraph also said Kerberos "descended from MIT's 1988 Athena project": MIT's own [Athena history](https://web.mit.edu/acs/athena.html) records that "In May 1983, MIT announced the establishment of a five-year program to explore new, innovative uses of computing in the MIT curriculum" and that "Project Athena, as the program was called, arose from this concern"; 1988 is the year of the first Kerberos paper — Steiner, Neuman and Schiller, "Kerberos: An Authentication Service for Open Network Systems", USENIX Winter Conference, Dallas, February 1988, as cited by RFC 4120 [SNS88] and by [MIT's Kerberos papers page](https://web.mit.edu/kerberos/papers.html). (The ACM and Elsevier abstract pages refused automated fetches with HTTP 403; the bibliographic facts and abstract sentences above come from the Crossref records the publishers deposited for those DOIs, cross-checked against the RFC 4120 reference list.)

## When to Use It

- Enterprise single sign-on with a central identity authority - what Active Directory and FreeIPA actually run on.
- Environments where every client can reach the KDC but not every service can reach every identity provider - the TGT caches authenticated sessions.
- Cross-realm trust with explicit delegation - a structured answer to the "one federation to rule them all" problem.
- Do NOT use Kerberos when clients can't sync to within 5 minutes of the KDC - skew failures are unforgiving.
- Do NOT use Kerberos-only for internet-scale authentication - token-based protocols (OIDC, OAuth) compose better with HTTP.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-kerberos](https://systemslibrarian.github.io/crypto-lab-kerberos/)**

Users can step through the original Needham-Schroeder flow, watch the Lowe attack succeed against it, then apply Lowe's fix and watch **the same relay re-run against the patched protocol** — Mallory is still on the wire, Bob still answers, and Alice aborts at message 2 on the identity mismatch. From there, run the full Kerberos v5 AS/TGS/AP flow with real AES-256-CTS-HMAC-SHA1 encrypted tickets, pre-authentication, and a replay button that re-submits the captured AP-REQ bytes verbatim. The clock can be skewed live to watch replay and expiration defenses fire.

The lab is built as a clickable timeline of four eras. The first three are one story — protocol published, attack found, one-line fix. Kerberos is not the redesign that followed: it comes from the shared-key side of the same 1978 paper, hardened by Denning-Sacco timestamps, and its v5 specification (RFC 1510, 1993) predates Lowe's attack. The rail says so on screen. Teaching aids layered on top for a first-time reader:

1. **Timeline + message flow** — pick an era (Needham-Schroeder (public-key) 1978, Lowe attack 1995, Lowe fix 1995, Kerberos v5 1993 → 2005) and watch its swimlane play out message by message.
2. **Lowe re-seal capsule** — when Mallory relays a message, an on-screen capsule shows the outer public-key envelope changing (`_pkM` → `_pkB`) while the sealed inner secret stays untouched, making "relay without decrypting" visible.
3. **Crypto-changed signpost** — an anchored banner fires the moment you enter the Kerberos scenario, naming the shift from per-party public keys to a trusted KDC with symmetric session keys — and the change of lineage, from the public-key protocol Lowe broke to the shared-key protocol Kerberos actually descends from (RFC 4120 §1).
4. **Three-exchange orientation card** — a "why three round-trips" primer (AS / TGS / AP) shown before the six-message flow, so the complexity is sequenced, not dumped.
5. **Grouped threat model** — the attack outcomes are grouped by the defense that stops them (replay / clock skew / ticket expiry / key theft / the public-key Needham-Schroeder flaw), each an expandable card with "what an attacker tries" vs "what stops them", and hoverable definitions for terms like Kerberoasting, pass-the-ticket, and AS-REP roasting.
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
- **Pre-authentication is PA-ENC-TIMESTAMP only.** No PKINIT, no FAST armoring, no hardware or OTP pre-auth types. The AS exchange is modelled on the KDC clock, so the clock slider demonstrates skew at the AP exchange; a real KDC would also reject a skewed AS-REQ — MIT krb5 answers that one with `KRB_AP_ERR_SKEW` (code 37) and reserves `KDC_ERR_PREAUTH_FAILED` for a timestamp that did not decrypt.
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
- **AES-CBC-CTS** — all six [RFC 3962 Appendix B](https://www.rfc-editor.org/rfc/rfc3962.html#appendix-B)
  ciphertext vectors, checked independently for encryption and decryption,
  including the final-two-block swap for aligned 32-, 48-, and 64-byte inputs
  (`test/cts.test.ts`).
- **Protocol behaviour** — the Lowe attack succeeds against Needham-Schroeder
  and the *same relay* is blocked by the one-line fix (both directions are
  asserted, so the test fails if either regresses); a captured AP-REQ
  re-submitted byte-for-byte still decrypts and HMAC-verifies but is refused on
  freshness; pre-authentication gates the AS-REP and the `pre-authent` flag; and
  the Kerberos clock-skew / replay / expiry defenses each fire
  (`test/protocols.test.ts`).

The same RFC 3962 §B string-to-key vector also runs live in the browser on every
page load (the **Self-check** panel), so visitors can watch the in-browser
derivation reproduce the published key. CI (`.github/workflows/deploy.yml`) runs the
type-checker and the full suite on every push and pull request, and the Pages deploy
names that job in `needs:`, so a failure ships nothing.

You can run the same checks locally:

```bash
npm run check    # type-check + full test suite
```

## Landing Page Card

- Category: Authentication Protocols
- Chips: Kerberos (RFC 4120) · Needham-Schroeder · Lowe Attack · AES-CTS-HMAC-SHA1
- One-line description: "Public-key Needham-Schroeder 1978 and the Lowe attack 1995, then Kerberos v5 - a separate lineage, from the shared-key Needham-Schroeder protocol via Denning-Sacco timestamps - with real AES-256-CTS-HMAC-SHA1 tickets, replay cache, clock skew, and the protocol Active Directory still runs on."

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
