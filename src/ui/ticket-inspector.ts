import type { EncTicket, TicketBody } from '../principals/kdc';

function escape(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string));
}

function fmt(ts: number): string {
  const d = new Date(ts);
  const pad = (n: number): string => n.toString().padStart(2, '0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}Z`;
}

function dur(ms: number): string {
  if (ms < 0) return 'expired';
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return `${h}h ${m}m`;
}

function hexBlock(bytes: Uint8Array): string {
  const hex = Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
  return hex.match(/.{1,32}/g)?.join('\n') ?? hex;
}

function row(label: string, value: string, extraClass = ''): string {
  return `<div class="ticket-line ${extraClass}"><span>${escape(label)}</span><code>${value}</code></div>`;
}

function flagsRow(flags: string[]): string {
  const chips = flags.map((f) => `<span class="flag">${escape(f)}</span>`).join('');
  return `<div class="ticket-line"><span>flags</span><div class="flag-row">${chips}</div></div>`;
}

function cipherRow(cipher: Uint8Array): string {
  const HMAC_BYTES = 12; // HMAC-SHA1-96 truncation
  const headLen = Math.min(32, Math.max(0, cipher.length - HMAC_BYTES));
  const head = cipher.subarray(0, headLen);
  const tail = cipher.subarray(cipher.length - HMAC_BYTES);
  const headHex = escape(hexBlock(head));
  const tailHex = escape(hexBlock(tail));
  return `<div class="ticket-line cipher"><span>cipher</span><code>${headHex}
<span class="cipher-note">… ${cipher.length - headLen - HMAC_BYTES} body bytes elided …</span>
<span class="cipher-note hmac">HMAC-SHA1-96 (${HMAC_BYTES} bytes):</span>
${tailHex}</code></div>`;
}

export function renderTicketInspector(ticket: EncTicket, body: TicketBody, nowMs: number): string {
  const remaining = body.endtime - nowMs;
  return `<div class="klist">
    ${row('realm', escape(body.realm))}
    ${row('client', escape(body.client_principal))}
    ${row('service', escape(body.sname))}
    ${row('etype', `${ticket.etype} (aes256-cts-hmac-sha1-96)`)}
    ${row('kvno', String(ticket.kvno))}
    ${row('authtime', escape(fmt(body.authtime)))}
    ${row('starttime', escape(fmt(body.starttime)))}
    ${row('endtime', `${escape(fmt(body.endtime))} <span style="color: var(--text-mute); margin-left: 8px;">(${escape(dur(remaining))} remaining)</span>`)}
    ${flagsRow(body.flags)}
    ${row('session key', escape(body.session_key_hex.slice(0, 32) + '… (32 bytes)'))}
    ${cipherRow(ticket.cipher)}
  </div>`;
}
