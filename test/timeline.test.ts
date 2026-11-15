import { describe, expect, it } from 'vitest';
import { renderTimeline, SCENARIOS } from '../src/app';

/**
 * The timeline rail is the lab's history exhibit, so its data is held to the
 * primary sources: RFC 4120 §1 (Kerberos is based on Needham and Schroeder's
 * trusted-third-party protocol with Denning and Sacco's modifications), §1.1
 * (conventional, shared-secret-key cryptography), RFC 1510 (September 1993),
 * RFC 4120 (July 2005), and Lowe, IPL 56(3), November 1995 — an attack on the
 * PUBLIC-KEY Needham-Schroeder protocol, two years after Kerberos v5 was
 * specified. The four eras are two lineages, and nothing here may say that one
 * led to the next.
 */

function scenario(key: string) {
  const s = SCENARIOS.find((x) => x.key === key);
  expect(s, `no scenario ${key}`).toBeTruthy();
  return s!;
}

describe('timeline data', () => {
  it('keeps the four runnable eras in their order', () => {
    expect(SCENARIOS.map((s) => s.key)).toEqual(['ns', 'lowe-attack', 'lowe-fix', 'kerberos']);
  });

  it('names the first era as the public-key protocol and points Kerberos at the shared-key one', () => {
    const ns = scenario('ns');
    expect(ns.label).toBe('Needham-Schroeder (public-key)');
    expect(ns.year).toBe('1978');
    expect(ns.blurb).toContain('shared-key protocol, not this one, is the ancestor of Kerberos');
  });

  it('dates Kerberos v5 to RFC 1510 (1993) and RFC 4120 (2005), before and after Lowe', () => {
    const k = scenario('kerberos');
    expect(k.year).toBe('1993 → 2005');
    expect(k.blurb).toContain('RFC 1510 (September 1993)');
    expect(k.blurb).toContain('RFC 4120 (July 2005)');
    expect(k.blurb).toContain('two years before Lowe’s attack');
  });

  it('gives Kerberos its own lineage: shared-key Needham-Schroeder plus Denning-Sacco timestamps', () => {
    const k = scenario('kerberos');
    expect(k.blurb).toContain('A separate lineage, not the step after Lowe');
    expect(k.blurb).toContain('shared-key Needham-Schroeder protocol with Denning & Sacco’s 1981 timestamps (RFC 4120 §1)');
  });

  it('makes no claim that one era led to the next', () => {
    for (const s of SCENARIOS) {
      expect(s.blurb, s.key).not.toMatch(/47[- ]year|\barc\b|because the previous|→ Kerberos/i);
    }
  });
});

describe('renderTimeline', () => {
  it('renders every era as a step, in order, with the active one marked', () => {
    const html = renderTimeline('kerberos');
    const keys = [...html.matchAll(/data-key="([a-z-]+)"/g)].map((m) => m[1]);
    expect(keys).toEqual(SCENARIOS.map((s) => s.key));
    expect(html).toContain('<li data-key="kerberos" class="active">');
    expect(html.match(/aria-current="true"/g)).toHaveLength(1);
  });

  it('heads the rail "Two lineages", not a single arc', () => {
    const html = renderTimeline('ns');
    expect(html).toContain('<span class="kicker">Two lineages</span>');
    expect(html).not.toContain('47 years');
  });

  it('states the Kerberos lineage and chronology in the rail note', () => {
    const html = renderTimeline('ns');
    expect(html).toContain('class="timeline-note"');
    expect(html).toContain('The first three steps are one story');
    expect(html).toContain('descends from the shared-key Needham-Schroeder protocol via Denning &amp; Sacco’s 1981 timestamps (RFC 4120 §1)');
    expect(html).toContain('Kerberos v5 (RFC 1510, 1993) predates Lowe’s attack');
  });

  it('shows the Kerberos dates in the rail', () => {
    expect(renderTimeline('ns')).toContain('<span class="year">1993 → 2005</span>');
  });
});
