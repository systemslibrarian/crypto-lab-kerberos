import type { FlowRecord, KerberosParty } from '../protocols/kerberos-v5';
import type { NSMessage, NSPrincipalName } from '../protocols/needham-schroeder';

function escape(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string));
}

function jsonPretty(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function trimHex(hex: string, max = 96): string {
  if (hex.length <= max) return hex;
  return `${hex.slice(0, max)}… (${hex.length / 2} bytes)`;
}

function chips(decoded: Record<string, unknown>): string {
  return Object.entries(decoded)
    .map(([k, v]) => {
      const val = typeof v === 'string' ? trimHex(v, 64) : Array.isArray(v) ? v.join(', ') : String(v);
      return `<span class="chip"><b>${escape(k)}</b><code>${escape(val)}</code></span>`;
    })
    .join('');
}

function laneStyle(parties: readonly string[], from: string, to: string): { style: string; reverse: boolean } {
  const fi = parties.indexOf(from) + 1;
  const ti = parties.indexOf(to) + 1;
  const a = Math.min(fi, ti);
  const b = Math.max(fi, ti);
  return {
    style: `--from: ${a}; --to: ${b + 1};`,
    reverse: ti < fi,
  };
}

function arrowText(from: string, to: string, label: string, reverse: boolean): string {
  const left = reverse ? to : from;
  const right = reverse ? from : to;
  const head = `<span class="arrow-head" aria-hidden="true"></span>`;
  return `<span class="arrow-tip">${escape(left)}</span><span class="arrow-line" aria-hidden="true"></span><span class="arrow-label">${escape(label)}</span><span class="arrow-line" aria-hidden="true"></span>${head}<span class="arrow-tip">${escape(right)}</span>`;
}

function header(parties: readonly string[], dimSet: ReadonlySet<string> = new Set()): string {
  return `<div class="swim-header" style="--cols: ${parties.length}">${parties
    .map((p) => `<div class="party ${dimSet.has(p) ? 'dim' : ''}">${escape(p)}</div>`)
    .join('')}</div>`;
}

function step(
  parties: readonly string[],
  scenarioClass: string,
  num: number,
  from: string,
  to: string,
  label: string,
  narrative: string,
  decoded: Record<string, unknown>,
  payloadHex: string,
): string {
  const { style, reverse } = laneStyle(parties, from, to);
  const lanes = parties.map(() => '<div class="lane"></div>').join('');
  return `
    <div class="swim-step ${scenarioClass}" style="--cols: ${parties.length}; --i: ${num};">
      ${lanes}
      <div class="swim-arrow ${reverse ? 'reverse' : ''}" style="${style}">
        <span class="step-num">${num}</span>
        ${arrowText(from, to, label, reverse)}
      </div>
      <div class="swim-payload">
        <div class="narrative">${narrative}</div>
        <div class="chips">${chips(decoded)}</div>
        <details><summary>Raw bytes · decoded JSON</summary>
          <pre>${escape(trimHex(payloadHex, 240))}</pre>
          <pre>${escape(jsonPretty(decoded))}</pre>
        </details>
      </div>
    </div>`;
}

// ── Needham-Schroeder family ───────────────────────────────
const NS_PARTIES: readonly NSPrincipalName[] = ['Alice', 'Mallory', 'Bob'];

function nsNarrative(m: NSMessage): string {
  const map: Record<string, string> = {
    'A -> B: {Na, A}_pkB': '<b>Alice</b> picks a fresh nonce <b>N<sub>a</sub></b> and sends it with her name, encrypted under Bob\u2019s public key. Only Bob can read it.',
    'A -> M: {Na, A}_pkM': '<b>Alice</b> initiates with <b>Mallory</b> (whom she trusts as a peer), sending her nonce encrypted under Mallory\u2019s key.',
    'M -> B: {Na, A}_pkB': '<b>Mallory</b> re-encrypts the inner payload under <b>Bob\u2019s</b> key and forwards it. Bob now thinks he\u2019s talking to Alice — the message looks identical to the legitimate one.',
    'B -> A: {Na, Nb}_pkA': '<b>Bob</b> echoes <b>N<sub>a</sub></b> back and adds his own nonce <b>N<sub>b</sub></b>. The original protocol does not name Bob inside this message — that is the <em>flaw</em>.',
    'B -> A: {Na, Nb, B}_pkA': 'The Lowe fix in one line: <b>Bob includes his identity</b> alongside the nonces. Now Alice can detect she\u2019s actually talking to someone other than Bob.',
    'B -> M: {Na, Nb}_pkA': 'Bob encrypts the response under Alice\u2019s public key — but he sends it back to Mallory (since the network address came from her).',
    'M -> A: {Na, Nb}_pkA': '<b>Mallory cannot decrypt this</b> (it\u2019s under Alice\u2019s key) — but doesn\u2019t need to. She just relays it. Alice sees a valid response from "Mallory" carrying her nonce.',
    'A -> B: {Nb}_pkB': 'Alice proves she received <b>N<sub>b</sub></b> by sending it back encrypted to Bob. Both parties now believe they share secret nonces.',
    'A -> M: {Nb}_pkM': 'Alice replies to Mallory with <b>N<sub>b</sub></b> — she learned it from "Mallory\u2019s" message. Mallory now knows Bob\u2019s nonce.',
    'M -> B: {Nb}_pkB': 'Mallory re-encrypts <b>N<sub>b</sub></b> under Bob\u2019s key. <b>Bob authenticates the run as Alice</b> even though Alice was never speaking to him.',
  };
  return map[m.label] ?? escape(m.label);
}

export function renderNsFlow(messages: NSMessage[]): string {
  // Always reserve all three lanes so the layout doesn't shift when switching scenarios.
  const parties = NS_PARTIES;
  const involved = new Set<string>();
  for (const m of messages) { involved.add(m.from); involved.add(m.to); }
  const dim = new Set(parties.filter((p) => !involved.has(p)));
  const scenarioClass = involved.has('Mallory') ? 'scenario-lowe-attack' : 'scenario-ns';
  const steps = messages
    .map((m) => step(parties, scenarioClass, m.step, m.from, m.to, m.label, nsNarrative(m), m.decoded, m.payloadHex))
    .join('');
  return `<div class="swim">${header(parties, dim)}${steps}</div>`;
}

// ── Kerberos v5 ────────────────────────────────────────────
const KRB_PARTIES: readonly KerberosParty[] = ['Client', 'KDC', 'Service'];

function krbNarrative(label: string): string {
  const map: Record<string, string> = {
    'AS-REQ': '<b>Client</b> asks the KDC\u2019s Authentication Service for a Ticket-Granting Ticket. No password is sent — just the principal name, realm, and a nonce.',
    'AS-REP': 'KDC returns the <b>TGT</b> (encrypted with the krbtgt key — opaque to the client) plus a session key encrypted under the client\u2019s long-term key, derived from the password via PBKDF2-HMAC-SHA1 × 4096.',
    'TGS-REQ': 'Client presents the TGT plus a fresh <b>authenticator</b> (cname + ctime) encrypted under the TGS session key, requesting a ticket for <code>http/web.lab.example</code>.',
    'TGS-REP': 'KDC validates the authenticator, mints a <b>service ticket</b> encrypted under the service\u2019s long-term key, and returns a new session key for client⇄service.',
    'AP-REQ': 'Client sends the service ticket to the application server with a <b>fresh authenticator</b> proving it currently holds the session key. Replay cache + clock skew are checked here.',
    'AP-REP': 'Service decrypts the authenticator, confirms <b>ctime / cusec</b>, and returns its own encrypted timestamp. <b>Mutual authentication</b> achieved.',
  };
  return map[label] ?? escape(label);
}

export function renderKerberosFlow(records: FlowRecord[]): string {
  const steps = records
    .map((r, idx) =>
      step(KRB_PARTIES, 'scenario-kerberos', idx + 1, r.from, r.to, r.label, krbNarrative(r.label), r.decoded, r.bytesHex),
    )
    .join('');
  return `<div class="swim">${header(KRB_PARTIES)}${steps}</div>`;
}
