import { runLoweAttack } from '../attacks/lowe-attack';
import { detectReplay } from '../attacks/replay-defense';
import { detectClockSkew, passTheTicket, validateTimeWindow } from '../attacks/skew-attack';
import { decryptAes256CtsHmacSha196 } from '../crypto/etype-aes256';
import { stringToKeyAes256 } from '../crypto/pbkdf2-string2key';
import { KeyDistributionCenter } from '../principals/kdc';
import { runLoweAttackAgainstFix } from '../protocols/lowe-fix';
import { buildNsKeys } from '../protocols/needham-schroeder';

function escape(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string));
}

// A jargon term with a short, hoverable/focusable definition. We use <abbr> with
// a title (native tooltip + screen-reader support) plus a dotted underline so the
// affordance is visible, not colour-only. The term itself stays in the sentence
// so nothing is hidden from a reader who never hovers.
function term(word: string, definition: string): string {
  return `<abbr class="jargon" title="${escape(definition)}">${escape(word)}</abbr>`;
}

interface DefenseCard {
  id: string;
  label: string;
  // The pass/fail glyph is set from the honest computed outcome, never
  // hardcoded: every `ok` below is derived from a value produced by running the
  // attack in this browser, and every `detail` is the string that run returned.
  ok: boolean;
  attack: string; // "what an attacker tries" (may contain <abbr> tooltips)
  stops: string; // "what stops them"
  detail: string; // the live computed reason string from the real defense code
}

function card(c: DefenseCard, open: boolean): string {
  const state = c.ok ? 'ok' : 'bad';
  const glyph = c.ok ? '✓' : '✗';
  const word = c.ok ? 'Defended' : 'Not defended';
  return `<details class="defense-card ${state}"${open ? ' open' : ''}>
    <summary>
      <span class="defense-glyph" aria-hidden="true">${glyph}</span>
      <span class="sr-only">${word}: </span>
      <span class="defense-label">${c.label}</span>
      <span class="defense-tag">${word}</span>
    </summary>
    <div class="defense-body">
      <p class="defense-line attack"><span class="defense-key">Attacker tries</span>${c.attack}</p>
      <p class="defense-line stops"><span class="defense-key">What stops them</span>${c.stops}</p>
      <p class="defense-detail"><span class="defense-key">Live result</span><code>${escape(c.detail)}</code></p>
    </div>
  </details>`;
}

// The AS-REP-roasting card is an exhibit, not an assertion: a throwaway KDC
// issues an AS-REP for an account with pre-auth switched OFF, and we crack the
// returned enc-part offline from this wordlist. The HMAC in the AES-256-CTS
// ciphertext is the oracle — a candidate password is confirmed when the
// derived key makes it verify. Ordered so the hit is not the first guess.
const ROAST_WORDLIST = ['Password1', 'letmein', 'Summer2024!', 'hunter2'];
const ROAST_PASSWORD = 'Summer2024!';
const ROAST_REALM = 'LEGACY.EXAMPLE';
const ROAST_ACCOUNT = 'svc-legacy';
const KU_AS_REP_ENCPART = 3;

type RoastResult = {
  /** The KDC answered an AS-REQ that carried no PA-DATA at all. */
  issuedWithoutPreauth: boolean;
  crackedPassword: string | null;
  guesses: number;
  /** The live error a pre-auth-required account returns to the same request. */
  preauthRefusal: string;
};

async function runAsRepRoast(nowMs: number): Promise<RoastResult> {
  const kdc = new KeyDistributionCenter(ROAST_REALM);
  await kdc.registerUser(ROAST_ACCOUNT, ROAST_PASSWORD, { requirePreauth: false });
  await kdc.registerUser('alice', 'correct-horse-battery-staple');

  // 1. An unauthenticated request, no PA-DATA. A pre-auth-disabled account
  //    answers it — that is the whole hole.
  let issuedWithoutPreauth = false;
  let encPart: Uint8Array | null = null;
  try {
    const rep = await kdc.issueAsRep(ROAST_ACCOUNT, 'attacker-nonce', nowMs, 8 * 60 * 60 * 1000);
    issuedWithoutPreauth = true;
    encPart = rep.encPartForClient;
  } catch {
    issuedWithoutPreauth = false;
  }

  // 2. Offline dictionary attack on the enc-part. No KDC involvement.
  let crackedPassword: string | null = null;
  let guesses = 0;
  if (encPart) {
    for (const candidate of ROAST_WORDLIST) {
      guesses += 1;
      const key = await stringToKeyAes256(candidate, `${ROAST_REALM}${ROAST_ACCOUNT}`);
      try {
        await decryptAes256CtsHmacSha196(key, KU_AS_REP_ENCPART, encPart);
        crackedPassword = candidate;
        break;
      } catch {
        // HMAC did not verify: wrong password, keep guessing.
      }
    }
  }

  // 3. The same unauthenticated request against an account that requires
  //    pre-auth. The refusal string below is whatever the KDC really returned.
  let preauthRefusal = 'AS-REP issued anyway';
  try {
    await kdc.issueAsRep('alice', 'attacker-nonce', nowMs, 8 * 60 * 60 * 1000);
  } catch (e) {
    preauthRefusal = e instanceof Error ? e.message : String(e);
  }

  return { issuedWithoutPreauth, crackedPassword, guesses, preauthRefusal };
}

export async function renderAttackPanel(nowMs: number, serviceEndtime: number): Promise<string> {
  const keys = await buildNsKeys();
  const lowe = await runLoweAttack(keys);
  const loweVsFix = await runLoweAttackAgainstFix(keys);
  const roast = await runAsRepRoast(nowMs);

  const sessionKey = new Uint8Array(32);
  crypto.getRandomValues(sessionKey);
  const cache = new Map<string, number>();
  const auth = { cname: 'alice', ctime: nowMs, cusec: 777 };
  const first = await detectReplay(sessionKey, auth, cache, nowMs, 5 * 60 * 1000);
  const second = await detectReplay(sessionKey, auth, cache, nowMs + 500, 5 * 60 * 1000);

  const skew = detectClockSkew(nowMs + 10 * 60 * 1000, nowMs, 5 * 60 * 1000);
  // An EXPIRED ticket, so the expiry defense has something to defend against:
  // the real service-ticket endtime, presented an hour after it lapsed.
  const expiredProbeMs = serviceEndtime + 60 * 60 * 1000;
  const validity = validateTimeWindow(nowMs - 60_000, serviceEndtime, expiredProbeMs, 5 * 60 * 1000);
  const ptt = passTheTicket(serviceEndtime, nowMs + 2 * 60 * 1000);

  // Grouped by the mechanism that defends (or fails to defend) — replay / skew /
  // expiry / key-theft — instead of seven terse one-liners in a flat list. Each
  // card leads with the threat, then the defense, then the live computed result.
  const groups: { title: string; note: string; cards: DefenseCard[] }[] = [
    {
      title: 'Replay',
      note: 'Reusing a captured message that was valid the first time.',
      cards: [
        {
          id: 'replay-1', label: 'First authenticator', ok: true,
          attack: `Capture a valid <b>authenticator</b> (a timestamped token proving the client holds the session key) off the wire, intending to resend it.`,
          stops: `Nothing yet — the <em>first</em> use is legitimate and accepted. The service records its <code>(cname, ctime, cusec)</code> tuple.`,
          detail: first.reason,
        },
        {
          id: 'replay-2', label: 'Replayed authenticator', ok: !second.accepted,
          attack: `Resend the identical authenticator a moment later. The ciphertext and HMAC still verify perfectly.`,
          stops: `The <b>replay cache</b>: the service already stored that exact tuple, so the duplicate is refused even though the crypto is valid.`,
          detail: second.reason,
        },
      ],
    },
    {
      title: 'Clock skew',
      note: 'Every authenticator is timestamped; the service and client clocks must agree.',
      cards: [
        {
          id: 'skew', label: 'Out-of-window timestamp', ok: !skew.accepted,
          attack: `Present an authenticator whose <code>ctime</code> is 10 minutes off the service clock — e.g. a very old capture, or a client with a wrong clock.`,
          stops: `The <b>±5-minute skew window</b>: timestamps outside it are rejected outright. This is also what bounds how long a captured authenticator stays replay-able.`,
          detail: skew.reason,
        },
      ],
    },
    {
      title: 'Ticket expiry',
      note: 'Tickets are short-lived; possession alone is not enough forever.',
      cards: [
        {
          id: 'window', label: 'Ticket validity window', ok: !validity.accepted,
          attack: `Use a ticket past its <code>endtime</code>, hoping the service does not check. Run live against <em>this page's</em> service ticket, presented one hour after it lapses.`,
          stops: `The service checks <code>starttime ≤ now ≤ endtime</code> (plus the skew allowance). An expired ticket forces the client back to the KDC for a fresh one.`,
          detail: validity.reason,
        },
        {
          id: 'ptt', label: term('Pass-the-ticket', 'An attack where a stolen but still-valid service ticket is reused directly — possession of the ticket material is sufficient to authenticate as its owner until it expires.'), ok: !ptt.accepted,
          attack: `Steal a still-valid service ticket from a client and present it yourself — Kerberos has no binding to the machine, so possession = access.`,
          stops: `Only <b>expiry</b>. This is an honest caveat, not a solved problem: within the ticket lifetime, ${term('pass-the-ticket', 'Reusing stolen, still-valid Kerberos ticket material to impersonate its owner.')} works. Short lifetimes and endpoint protection are the real mitigations.`,
          detail: ptt.reason,
        },
      ],
    },
    {
      title: 'Key theft & offline cracking',
      note: 'Pre-authentication decides whether an attacker gets password-derived ciphertext at all; once they have it, only key strength is left. Both cards below are run live against a throwaway KDC.',
      cards: [
        {
          id: 'roast',
          label: term('AS-REP roasting', 'When Kerberos pre-authentication is disabled for an account, the KDC returns an AS-REP whose encrypted part is derived from the user password — an attacker can request it unauthenticated and crack the password offline.'),
          ok: roast.crackedPassword === null,
          attack: `Find an account with ${term('pre-authentication', 'A first step where the client proves knowledge of its key (via an encrypted timestamp) BEFORE the KDC replies, so no password-derived ciphertext is handed to an unauthenticated requester.')} disabled, request its AS-REP unauthenticated, and crack the password-derived <code>enc-part</code> offline. <b>This card does exactly that</b>, live: a throwaway KDC in the realm <code>${escape(ROAST_REALM)}</code> issues an AS-REP for <code>${escape(ROAST_ACCOUNT)}</code>, and a ${ROAST_WORDLIST.length}-word dictionary is run against it in your browser.`,
          stops: `Nothing here — that is the point. <b>Pre-auth</b> would have refused the request (see the next card) and a <b>strong password</b> would have survived the dictionary. Closely related: ${term('Kerberoasting', 'Requesting a service ticket for a service account and cracking it offline, because the ticket is encrypted under the service account key derived from its (often weak) password.')} cracks service-ticket keys the same way. No protocol check saves a weak key — only entropy does.`,
          detail: roast.crackedPassword === null
            ? `AS-REP issued without PA-DATA: ${roast.issuedWithoutPreauth}; ${roast.guesses} candidates tried, none verified`
            : `AS-REP issued without PA-DATA, enc-part cracked offline after ${roast.guesses} guesses → "${roast.crackedPassword}"`,
        },
        {
          id: 'preauth',
          label: 'The same request, pre-auth required',
          ok: roast.preauthRefusal.includes('PREAUTH_REQUIRED'),
          attack: `Point the identical unauthenticated AS-REQ at an account that <em>does</em> require pre-authentication, hoping for the same password-derived ciphertext to crack.`,
          stops: `<b>PA-ENC-TIMESTAMP</b>: the KDC will not emit an <code>enc-part</code> until the requester proves it already holds the client key by encrypting a timestamp with it. With nothing to hand out, there is nothing to crack offline. This demo's own <code>alice</code> uses this path — which is why her tickets carry the <code>pre-authent</code> flag in the inspector above.`,
          detail: roast.preauthRefusal,
        },
      ],
    },
    {
      title: 'The pre-Kerberos flaw',
      note: 'Why Kerberos exists at all — the bug in the public-key protocol it replaced, and the patch that closed it.',
      cards: [
        {
          id: 'lowe', label: 'Lowe man-in-the-middle (unpatched Needham-Schroeder)', ok: !lowe.bobAccepted,
          attack: `Relay Alice’s messages to Bob without decrypting the inner secret, so Bob authenticates the run as Alice (the 1995 Lowe attack).`,
          stops: `Nothing, in the 1978 protocol — message 2 never names its sender, so Alice cannot tell Bob’s reply from a relayed one. In Kerberos the question does not arise: there is no per-party public-key handshake to man-in-the-middle.`,
          detail: `NS: Bob accepted forged run as Alice = ${lowe.bobAccepted}`,
        },
        {
          id: 'lowe-fix', label: 'The same attack, against Lowe’s fix', ok: loweVsFix.aliceAborted && !loweVsFix.bobAccepted,
          attack: `Run the identical relay against the patched protocol, where message 2 is <code>{N<sub>a</sub>, N<sub>b</sub>, <b>B</b>}<sub>pk(A)</sub></code>.`,
          stops: `<b>Identity binding.</b> Alice compares the name sealed inside message 2 against the peer she actually dialled, and aborts on the mismatch — so she never returns N<sub>b</sub> and Mallory has nothing to forward to Bob.`,
          detail: loweVsFix.aliceAborted
            ? `${loweVsFix.rejectedReason}; Bob accepted = ${loweVsFix.bobAccepted}`
            : `Alice completed the run with Mallory in the middle; Bob accepted = ${loweVsFix.bobAccepted}`,
        },
      ],
    },
  ];

  return groups
    .map(
      (g) => `<div class="defense-group">
        <h3 class="defense-group-title">${escape(g.title)}</h3>
        <p class="defense-group-note">${escape(g.note)}</p>
        ${g.cards.map((c, i) => card(c, i === 0)).join('')}
      </div>`,
    )
    .join('');
}
