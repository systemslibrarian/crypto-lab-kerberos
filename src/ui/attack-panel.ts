import { runLoweAttack } from '../attacks/lowe-attack';
import { detectReplay } from '../attacks/replay-defense';
import { detectClockSkew, passTheTicket, validateTimeWindow } from '../attacks/skew-attack';
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
  // The pass/fail glyph is set from the honest computed outcome, never hardcoded.
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

export async function renderAttackPanel(nowMs: number, serviceEndtime: number): Promise<string> {
  const keys = await buildNsKeys();
  const lowe = await runLoweAttack(keys);

  const sessionKey = new Uint8Array(32);
  crypto.getRandomValues(sessionKey);
  const cache = new Map<string, number>();
  const auth = { cname: 'alice', ctime: nowMs, cusec: 777 };
  const first = await detectReplay(sessionKey, auth, cache, nowMs, 5 * 60 * 1000);
  const second = await detectReplay(sessionKey, auth, cache, nowMs + 500, 5 * 60 * 1000);

  const skew = detectClockSkew(nowMs + 10 * 60 * 1000, nowMs, 5 * 60 * 1000);
  const validity = validateTimeWindow(nowMs - 60_000, serviceEndtime, nowMs + 10 * 60 * 1000, 5 * 60 * 1000);
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
          attack: `Use a ticket past its <code>endtime</code>, hoping the service does not check.`,
          stops: `The service checks <code>starttime ≤ now ≤ endtime</code>. An expired ticket forces the client back to the KDC for a fresh one.`,
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
      note: 'The defense here is key strength, not a protocol check — the honest weak spot.',
      cards: [
        {
          id: 'roast', label: term('AS-REP roasting', 'When Kerberos pre-authentication is disabled for an account, the KDC returns an AS-REP whose encrypted part is derived from the user password — an attacker can request it unauthenticated and crack the password offline.'), ok: false,
          attack: `Find an account with ${term('pre-authentication', 'An optional first step where the client proves knowledge of its key (via an encrypted timestamp) BEFORE the KDC replies, so no password-derived ciphertext is handed to an unauthenticated requester.')} disabled, request its AS-REP, and crack the password-derived <code>enc-part</code> offline.`,
          stops: `<b>Pre-auth</b> (require the client to prove its key first) plus <b>strong passwords</b>. Closely related: ${term('Kerberoasting', 'Requesting a service ticket for a service account and cracking it offline, because the ticket is encrypted under the service account key derived from its (often weak) password.')} cracks service-ticket keys the same way. No protocol check saves a weak key — only entropy does.`,
          detail: 'pre-auth disabled → password-derived enc-part is crackable offline',
        },
      ],
    },
    {
      title: 'The pre-Kerberos flaw',
      note: 'Why Kerberos exists at all — the bug in the public-key protocol it replaced.',
      cards: [
        {
          id: 'lowe', label: 'Lowe man-in-the-middle (Needham-Schroeder)', ok: !lowe.bobAccepted,
          attack: `Relay Alice’s messages to Bob without decrypting the inner secret, so Bob authenticates the run as Alice (the 1995 Lowe attack).`,
          stops: `In Kerberos, nothing needs to: there is no per-party public-key handshake to man-in-the-middle. The KDC and symmetric session keys sidestep the whole class of bug.`,
          detail: lowe.bobAccepted ? 'NS: Bob accepted forged run as Alice' : 'NS with Lowe fix: forged run rejected',
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
