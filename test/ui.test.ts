import { describe, expect, it } from 'vitest';
import { renderKerberosFlow, renderNsFlow } from '../src/ui/message-flow';
import type { NSMessage } from '../src/protocols/needham-schroeder';
import type { FlowRecord } from '../src/protocols/kerberos-v5';

const nsMessages: NSMessage[] = [
  { from: 'Alice', to: 'Bob', step: 1, label: 'A -> B: {Na, A}_pkB', payloadHex: 'aa', decoded: { Na: '1', A: 'Alice' } },
  { from: 'Bob', to: 'Alice', step: 2, label: 'B -> A: {Na, Nb, B}_pkA', payloadHex: 'bb', decoded: { Na: '1', Nb: '2', B: 'Bob' } },
];

describe('renderNsFlow scenario tinting', () => {
  it('applies the scenario class it is given (no Mallory-based guessing)', () => {
    // Regression: the Lowe-fix flow has no Mallory, and used to be mis-tinted as
    // scenario-ns (violet) instead of its own scenario-lowe-fix (teal).
    const html = renderNsFlow(nsMessages, 'scenario-lowe-fix');
    expect(html).toContain('swim-step scenario-lowe-fix');
    expect(html).not.toContain('scenario-ns');
  });

  it('defaults to scenario-ns when no class is passed', () => {
    expect(renderNsFlow(nsMessages)).toContain('swim-step scenario-ns');
  });

  it('escapes decoded values to prevent HTML injection', () => {
    const evil: NSMessage[] = [
      { from: 'Alice', to: 'Bob', step: 1, label: 'x', payloadHex: '00', decoded: { Na: '<img src=x onerror=alert(1)>' } },
    ];
    const html = renderNsFlow(evil, 'scenario-ns');
    expect(html).not.toContain('<img src=x');
    expect(html).toContain('&lt;img');
  });
});

describe('renderKerberosFlow', () => {
  it('tints every step as scenario-kerberos', () => {
    const records: FlowRecord[] = [
      { label: 'AS-REQ', from: 'Client', to: 'KDC', bytesHex: 'aa', decoded: { client: 'alice' } },
      { label: 'AP-REP', from: 'Service', to: 'Client', bytesHex: 'bb', decoded: { seq: 1 } },
    ];
    const html = renderKerberosFlow(records);
    expect(html).toContain('swim-step scenario-kerberos');
    expect(html.match(/scenario-kerberos/g)?.length).toBeGreaterThanOrEqual(2);
  });
});
