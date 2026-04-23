import type { FlowRecord } from '../protocols/kerberos-v5';
import type { NSMessage } from '../protocols/needham-schroeder';

function jsonPretty(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function msgCard(label: string, payloadHex: string, decoded: unknown): string {
  return `<article class="msg-card"><h4>${label}</h4><pre>${payloadHex}</pre><details><summary>Decoded</summary><pre>${jsonPretty(decoded)}</pre></details></article>`;
}

export function renderNsFlow(messages: NSMessage[]): string {
  return messages.map((m) => msgCard(`${m.step}. ${m.label}`, m.payloadHex, m.decoded)).join('');
}

export function renderKerberosFlow(records: FlowRecord[]): string {
  return records.map((r, idx) => msgCard(`${idx + 1}. ${r.label}`, r.bytesHex, r.decoded)).join('');
}
