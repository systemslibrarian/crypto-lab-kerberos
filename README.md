# crypto-lab-kerberos

## 1. What It Is
Kerberos (RFC 4120) is a trusted-third-party authentication protocol descended from MIT's 1988 Athena project. This demo walks the 47-year arc: Needham-Schroeder (1978) -> the Lowe attack (1995) -> Kerberos v5 with AES-256-CTS-HMAC-SHA1 (RFC 3962). The security model assumes a trusted Key Distribution Center (KDC) and synchronized clocks across all principals.

## 2. When to Use It
- Enterprise single sign-on with a central identity authority - what Active Directory and FreeIPA actually run on.
- Environments where every client can reach the KDC but not every service can reach every identity provider - the TGT caches authenticated sessions.
- Cross-realm trust with explicit delegation - a structured answer to the "one federation to rule them all" problem.
- Do NOT use Kerberos when clients can't sync to within 5 minutes of the KDC - skew failures are unforgiving.
- Do NOT use Kerberos-only for internet-scale authentication - token-based protocols (OIDC, OAuth) compose better with HTTP.

## 3. Live Demo
Link: https://systemslibrarian.github.io/crypto-lab-kerberos/

Users can step through the original Needham-Schroeder flow, watch the Lowe attack succeed against it, apply Lowe's fix and watch the attack fail, then run the full Kerberos v5 AS/TGS/AP flow with real AES-256-CTS-HMAC-SHA1 encrypted tickets. The clock can be skewed live to watch replay and expiration defenses fire.

## 4. How to Run Locally
```bash
git clone https://github.com/systemslibrarian/crypto-lab-kerberos
cd crypto-lab-kerberos
npm install
npm run dev      # live demo at http://localhost:5173
npm run check    # type-check + full test suite
```

## 5. Why You Can Trust the Crypto
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

## 6. Part of the Crypto-Lab Suite
> One of 100+ live browser demos at
> [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/)
> - spanning Atbash (600 BCE) through NIST FIPS 203/204/205 (2024).

## Landing Page Card
- Category: Authentication Protocols
- Chips: Kerberos (RFC 4120) · Needham-Schroeder · Lowe Attack · AES-CTS-HMAC-SHA1
- One-line description: "The 47-year arc from Needham-Schroeder 1978 through the Lowe attack 1995 to Kerberos v5 - real AES-256-CTS-HMAC-SHA1 tickets, replay cache, clock skew, and the protocol Active Directory still runs on."

---

*"Whether you eat or drink, or whatever you do, do all to the glory of God." - 1 Corinthians 10:31*
