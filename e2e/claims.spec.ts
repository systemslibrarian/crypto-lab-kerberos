import { expect, test, type Page } from '@playwright/test';

/**
 * Claims gate: the verdicts, nonces, tickets and defense outcomes this lab
 * renders, asserted against each other rather than against fixed strings.
 *
 * The a11y spec proves every scenario can be read. This one proves the story
 * is true: that Mallory's relay really does carry the same nonce bytes end to
 * end, that the Lowe fix aborts the same relay two messages earlier, that the
 * Kerberos flow's nonce/ctime/cusec echoes line up across six messages and
 * into the tickets, that the replay button is refused on the exact tuple the
 * AP-REQ published, that the skew badge and the AP verdict agree about ±5
 * minutes, and that every glyph in the threat panel matches the live result
 * printed underneath it — including the three that are honestly red.
 *
 * Nothing here hardcodes a nonce or a timestamp; they are generated per run.
 */

const HEAVY = 120_000;

/** Read the `<b>KEY</b><code>VALUE</code>` chips of one swimlane step. */
async function stepChips(page: Page, index: number): Promise<Map<string, string>> {
  return new Map(
    await page
      .locator('.swim-step')
      .nth(index)
      .locator('.chip')
      .evaluateAll((els) =>
        els.map((el): [string, string] => [
          el.querySelector('b')?.textContent?.trim() ?? '',
          el.querySelector('code')?.textContent?.trim() ?? '',
        ]),
      ),
  );
}

async function chip(page: Page, index: number, key: string): Promise<string> {
  const chips = await stepChips(page, index);
  const value = chips.get(key);
  expect(value, `step ${index + 1} has no ${key} chip (has ${[...chips.keys()].join(', ')})`).toBeTruthy();
  return value!;
}

/** The `.result` lines under a flow: pass/fail plus the text that explains it. */
async function results(page: Page): Promise<{ ok: boolean; text: string }[]> {
  return page.locator('#flow .flow-result').evaluateAll((els) =>
    els.map((el) => ({
      ok: el.className.includes('ok'),
      text: el.textContent?.trim() ?? '',
    })),
  );
}

/** Every klist row of one ticket inspector, keyed by its label. */
async function ticketRows(page: Page, panelIndex: number): Promise<Map<string, string>> {
  return new Map(
    await page
      .locator('#inspectors .panel')
      .nth(panelIndex)
      .locator('.ticket-line')
      .evaluateAll((els) =>
        els.map((el): [string, string] => [
          el.querySelector('span')?.textContent?.trim() ?? '',
          (el.querySelector('code') ?? el.querySelector('.flag-row'))?.textContent?.trim() ?? '',
        ]),
      ),
  );
}

/** Parse the inspector's `YYYY-MM-DD HH:MM:SSZ` stamps back to epoch ms. */
function parseStamp(value: string): number {
  const m = /(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})Z/.exec(value);
  expect(m, `not a ticket timestamp: ${value}`).not.toBeNull();
  return Date.parse(`${m![1]}T${m![2]}Z`);
}

/**
 * Scenario labels, used to wait for the *new* flow to land. The scenario class
 * is set synchronously but the flow is rebuilt after several awaits, so
 * without this a read races the previous scenario's DOM.
 */
const LABELS: Record<string, string> = {
  ns: 'Needham-Schroeder',
  'lowe-attack': 'Lowe Attack',
  'lowe-fix': 'Lowe Fix',
  kerberos: 'Kerberos v5',
};

async function selectScenario(page: Page, key: string): Promise<void> {
  await page.locator('#scenario').selectOption(key);
  await expect(page.locator('#flow')).toHaveClass(new RegExp(`scenario-${key}(\\s|$)`));
  await expect(page.locator('#flow h2')).toContainText(LABELS[key]!, { timeout: HEAVY });
  // Every scenario ends with at least one computed result line.
  await expect(page.locator('#flow .flow-result').first()).toBeVisible({ timeout: HEAVY });
}

async function runKerberos(page: Page): Promise<void> {
  await selectScenario(page, 'kerberos');
  await expect(page.locator('#inspectors')).toBeVisible({ timeout: HEAVY });
  await expect(page.locator('#attacks-wrap .defense-card')).not.toHaveCount(0, { timeout: HEAVY });
}

// ---------------------------------------------------------------------------
// Self-check — the lab's own claim that its crypto is trustworthy
// ---------------------------------------------------------------------------

test('the self-check runs real vectors and every one of them passes', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');

  const checks = page.locator('#selfcheck .check');
  await expect(checks).toHaveCount(4, { timeout: HEAVY });

  // No check may be red — the panel's own stated contract.
  await expect(page.locator('#selfcheck .check.bad')).toHaveCount(0);
  expect(await page.locator('#selfcheck .check.ok').count()).toBe(4);

  const rows = await checks.evaluateAll((els) =>
    els.map((el) => ({
      pip: el.querySelector('.pip')?.textContent?.trim() ?? '',
      name: el.querySelector('.name')?.textContent?.trim() ?? '',
      msg: el.querySelector('.msg')?.textContent?.trim() ?? '',
      ok: el.className.includes('ok'),
    })),
  );

  // The glyph must agree with the class it is drawn in.
  for (const row of rows) expect(row.pip).toBe(row.ok ? '✓' : '✗');

  // The published RFC 3962 §B string-to-key vector, byte-checked in-browser.
  const kat = rows.find((r) => r.name.includes('RFC 3962'));
  expect(kat?.msg).toBe('matches 55a6ac74…');

  expect(rows.find((r) => r.name.includes('AES-256-CTS'))?.msg).toMatch(/^\d+ bytes → ok$/);
  expect(rows.find((r) => r.name.includes('HMAC tamper'))?.msg).toBe('rejected forged ciphertext');
  // The end-to-end probe run is the same six-message exchange the flow renders.
  expect(rows.find((r) => r.name.includes('AS → TGS → AP'))?.msg).toBe('6 messages → ok');
});

// ---------------------------------------------------------------------------
// Needham-Schroeder, the Lowe attack, and the one-line fix
// ---------------------------------------------------------------------------

test('the honest Needham-Schroeder run carries its nonces through unchanged', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');
  await selectScenario(page, 'ns');

  await expect(page.locator('.swim-step')).toHaveCount(3);

  // Na travels message 1 -> 2; Nb travels message 2 -> 3. Same 32 hex digits
  // each time, which is what "the run authenticates" actually means here.
  const na1 = await chip(page, 0, 'Na');
  expect(na1).toMatch(/^[0-9a-f]{32}$/);
  expect(await chip(page, 1, 'Na')).toBe(na1);
  expect(await chip(page, 0, 'A')).toBe('Alice');

  const nb2 = await chip(page, 1, 'Nb');
  expect(nb2).toMatch(/^[0-9a-f]{32}$/);
  expect(nb2).not.toBe(na1);
  expect(await chip(page, 2, 'Nb')).toBe(nb2);

  const [verdict] = await results(page);
  expect(verdict?.ok).toBe(true);
  expect(verdict?.text).toContain('Bob accepted Alice as authenticated.');

  // The lab names the flaw it is about to exploit, in the message that has it.
  await expect(page.locator('.swim-step').nth(1)).toContainText('does not name Bob inside this message');

  // No clock control outside Kerberos — it means nothing to this protocol.
  await expect(page.locator('#clock-field')).toBeHidden();
});

test('the Lowe relay reaches Bob without ever changing the sealed nonce', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');
  await selectScenario(page, 'lowe-attack');

  await expect(page.locator('.swim-step')).toHaveCount(6);

  // README: "relay without decrypting". The same Na bytes appear in all four
  // messages that carry it, across two re-seals — and likewise Nb.
  const na = await chip(page, 0, 'Na');
  expect(na).toMatch(/^[0-9a-f]{32}$/);
  for (const step of [1, 2, 3]) expect(await chip(page, step, 'Na'), `Na changed at step ${step + 1}`).toBe(na);

  const nb = await chip(page, 2, 'Nb');
  expect(nb).toMatch(/^[0-9a-f]{32}$/);
  for (const step of [3, 4, 5]) expect(await chip(page, step, 'Nb'), `Nb changed at step ${step + 1}`).toBe(nb);

  // The capsule visual: Mallory opens what she can and relays what she cannot.
  const seals = await page
    .locator('.reseal')
    .evaluateAll((els) =>
      els.map((el) => ({
        from: el.querySelector('.reseal-seal.from')?.textContent?.trim() ?? '',
        to: el.querySelector('.reseal-seal.to')?.textContent?.trim() ?? '',
        lock: el.querySelector('.reseal-lock')?.textContent?.trim() ?? '',
      })),
    );
  expect(seals.length).toBeGreaterThan(0);
  for (const seal of seals) {
    // An open padlock only where the outer envelope is Mallory's own key.
    expect(seal.lock).toBe(seal.from === '_pkM' ? '🔓' : '🔒');
    if (seal.lock === '🔒') expect(seal.from).toBe(seal.to);
  }

  // The verdict is red, and it says both halves of the deception.
  const [verdict] = await results(page);
  expect(verdict?.ok).toBe(false);
  expect(verdict?.text).toContain('Bob accepted forged run: true');
  const believed = /Alice believed peer = (\w+)\. Bob believed peer = (\w+)\./.exec(verdict?.text ?? '');
  expect(believed, `verdict did not report both beliefs: ${verdict?.text}`).not.toBeNull();
  expect(believed![1]).toBe('Mallory');
  expect(believed![2]).toBe('Alice');
  expect(believed![1], 'the attack is that the two parties disagree about the peer').not.toBe(believed![2]);
});

test('the same relay against Lowe’s fix dies two messages early, and honest use survives', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');
  await selectScenario(page, 'lowe-attack');
  const attackSteps = await page.locator('.swim-step').count();

  await selectScenario(page, 'lowe-fix');
  const fixSteps = await page.locator('.swim-step').count();

  // Steps 5 and 6 of the attack never happen: Alice aborts at 4.
  expect(fixSteps).toBe(4);
  expect(attackSteps - fixSteps).toBe(2);

  // The patch is visible in the message that carries it: B is now sealed in.
  expect(await chip(page, 2, 'B')).toBe('Bob');
  expect(await chip(page, 3, 'B')).toBe('Bob');
  const na = await chip(page, 0, 'Na');
  expect(await chip(page, 3, 'Na'), 'the relay still reaches Alice unchanged').toBe(na);

  const lines = await results(page);
  expect(lines).toHaveLength(2);

  // The attack result is green *because* it was blocked, and names the reason.
  expect(lines[0]?.ok).toBe(true);
  expect(lines[0]?.text).toContain('Attack blocked at step 4');
  expect(lines[0]?.text).toContain('identity mismatch: message 2 names "Bob", Alice called Mallory');
  expect(lines[0]?.text).toContain('Bob accepted forged run: false');

  // README: this is not an attacker-free run relabelled — Mallory is still on
  // the wire, and the honest run is computed separately to prove the patch
  // did not break legitimate use.
  await expect(page.locator('.swim-header .party')).toContainText(['Alice', 'Mallory', 'Bob']);
  expect(lines[1]?.ok).toBe(true);
  expect(lines[1]?.text).toContain('Honest direct run');
  expect(lines[1]?.text).toContain('still completes in 3 messages');
});

// ---------------------------------------------------------------------------
// Kerberos v5 — the six-message flow and the tickets it mints
// ---------------------------------------------------------------------------

test('the Kerberos flow’s six messages echo each other’s nonce, ctime and cusec', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');
  await runKerberos(page);

  await expect(page.locator('.swim-step')).toHaveCount(6);

  // AS-REQ -> AS-REP: the nonce comes back, which is what binds the reply.
  const nonce = await chip(page, 0, 'nonce');
  expect(await chip(page, 1, 'nonce'), 'the AS-REP did not echo the AS-REQ nonce').toBe(nonce);
  expect(nonce).toContain('alice');

  // Pre-authentication is real: PA-ENC-TIMESTAMP is sent and the AS-REP says
  // the KDC verified it, which is what earns the pre-authent ticket flag.
  expect(await chip(page, 0, 'padata-type')).toBe('2 (PA-ENC-TIMESTAMP)');
  expect(await chip(page, 0, 'padata (enc-ts)')).toMatch(/^[0-9a-f]{64}… \(\d+ bytes\)$/);
  expect(await chip(page, 1, 'pre-authenticated')).toBe('true');
  expect(await chip(page, 1, 'sname')).toBe('krbtgt/LAB.EXAMPLE');
  expect(await chip(page, 1, 'etype')).toBe('18');

  // TGS-REP mints a ticket for the service the client asked for.
  expect(await chip(page, 3, 'sname')).toBe('http/web.lab.example');
  expect(await chip(page, 3, 'etype')).toBe('18');

  // AP-REQ -> AP-REP: mutual authentication is the service echoing back the
  // exact (ctime, cusec) the client's authenticator carried.
  const ctime = await chip(page, 4, 'ctime');
  const cusec = await chip(page, 4, 'cusec');
  expect(await chip(page, 5, 'ctime'), 'the AP-REP did not echo ctime').toBe(ctime);
  expect(await chip(page, 5, 'cusec'), 'the AP-REP did not echo cusec').toBe(cusec);
  expect(await chip(page, 4, 'cname')).toBe('alice');
  expect(await chip(page, 5, 'seq')).toBe('1');

  const [verdict] = await results(page);
  expect(verdict?.ok).toBe(true);
  expect(verdict?.text).toContain('AP exchange accepted.');
});

test('both tickets are consistent with the exchanges that minted them', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');
  await runKerberos(page);
  await expect(page.locator('#inspectors .panel')).toHaveCount(2);

  const tgt = await ticketRows(page, 0);
  const svc = await ticketRows(page, 1);

  for (const [name, rows] of [
    ['TGT', tgt],
    ['service ticket', svc],
  ] as const) {
    expect(rows.get('realm'), name).toBe('LAB.EXAMPLE');
    expect(rows.get('client'), name).toBe('alice');
    expect(rows.get('etype'), name).toBe('18 (aes256-cts-hmac-sha1-96)');
    expect(rows.get('kvno'), name).toBe('1');
    // The session key is a 32-byte AES-256 key, shown as its first 16 bytes.
    expect(rows.get('session key'), name).toMatch(/^[0-9a-f]{32}… \(32 bytes\)$/);

    // starttime <= endtime, and the "remaining" figure is endtime − now.
    const start = parseStamp(rows.get('starttime') ?? '');
    const end = parseStamp(rows.get('endtime') ?? '');
    expect(start, name).toBeLessThan(end);
    expect(parseStamp(rows.get('authtime') ?? ''), name).toBe(start);

    const remaining = /\((\d+)h (\d+)m remaining\)/.exec(rows.get('endtime') ?? '');
    expect(remaining, `${name}: no remaining figure in ${rows.get('endtime')}`).not.toBeNull();
    const remainingMs = (Number(remaining![1]) * 60 + Number(remaining![2])) * 60_000;
    expect(Math.abs(remainingMs - (end - start)), `${name}: lifetime and remaining disagree`).toBeLessThan(120_000);

    // The cipher is a real AES-256-CTS blob with the HMAC-SHA1-96 tag split
    // out: head + elided body + 12-byte tag must account for every byte.
    const cipher = rows.get('cipher') ?? '';
    const head = /^([0-9a-f\n]+)…/.exec(cipher)?.[1]?.replace(/\s/g, '') ?? '';
    const elided = Number(/… (\d+) body bytes elided …/.exec(cipher)?.[1]);
    const tag = /HMAC-SHA1-96 \(12 bytes\):\s*([0-9a-f]+)/.exec(cipher)?.[1] ?? '';
    expect(head.length / 2, name).toBe(32);
    expect(elided, name).toBeGreaterThan(0);
    expect(tag.length / 2, `${name}: HMAC tag is not 12 bytes`).toBe(12);
  }

  // Each ticket names the service its exchange asked for.
  expect(tgt.get('service')).toBe('krbtgt/LAB.EXAMPLE');
  expect(svc.get('service')).toBe('http/web.lab.example');

  // The endtimes the AS-REP and TGS-REP published are the ones in the tickets
  // (the inspector renders whole seconds, so compare at second resolution).
  const toSecond = (ms: number): number => Math.floor(ms / 1000) * 1000;
  expect(parseStamp(tgt.get('endtime') ?? '')).toBe(toSecond(Number(await chip(page, 1, 'endtime'))));
  expect(parseStamp(svc.get('endtime') ?? '')).toBe(toSecond(Number(await chip(page, 3, 'endtime'))));

  // The service ticket is derived from the TGT, so it cannot outlive it, and
  // its session key is a different key.
  expect(parseStamp(svc.get('endtime') ?? '')).toBeLessThan(parseStamp(tgt.get('endtime') ?? ''));
  expect(svc.get('session key')).not.toBe(tgt.get('session key'));

  // README: the pre-authent flag is earned by the AS exchange, and only the
  // TGT is `initial` — the service ticket came from the TGS, not a password.
  expect(tgt.get('flags')).toContain('pre-authent');
  expect(tgt.get('flags')).toContain('initial');
  expect(svc.get('flags')).toContain('pre-authent');
  expect(svc.get('flags')).not.toContain('initial');
});

// ---------------------------------------------------------------------------
// The replay defense
// ---------------------------------------------------------------------------

test('the replay button re-submits real bytes and is refused on the tuple it published', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');
  await runKerberos(page);

  const panel = page.locator('#replay-mount');
  await expect(panel).toBeVisible();

  // The panel's byte count is the AP-REQ it captured, and the cache holds the
  // one authenticator the accepted run put there.
  const intro = (await panel.textContent()) ?? '';
  const bytes = Number(/re-submits the (\d+) captured AP-REQ bytes/.exec(intro)?.[1]);
  expect(bytes).toBeGreaterThan(0);
  expect(Number(/Replay cache size: (\d+)/.exec(intro)?.[1])).toBe(1);

  const ctime = await chip(page, 4, 'ctime');
  const cusec = await chip(page, 4, 'cusec');

  await page.locator('#replay-btn').click();
  const badge = panel.locator('.badge');
  await expect(badge).toBeVisible({ timeout: HEAVY });

  // The failure verdict, and the reason: the crypto passed, freshness did not.
  await expect(badge).toHaveClass(/(^|\s)bad(\s|$)/);
  await expect(badge).toHaveText('rejected: replay cache hit');
  const note = (await panel.locator('.replay-note').textContent()) ?? '';
  expect(note).toContain(`AES-256-CTS decrypt + HMAC-SHA1-96 verify on ${bytes} resubmitted bytes: OK`);
  expect(note).toContain('the cryptography passed');
  expect(note).toContain(`(cname, ctime, cusec) = (alice, ${ctime}, ${cusec}) was already in the replay cache`);

  // Same refusal every time — it is a cache, not a one-shot.
  await page.locator('#replay-btn').click();
  await expect(panel.locator('.badge')).toHaveText('rejected: replay cache hit');
});

// ---------------------------------------------------------------------------
// The clock-skew defense
// ---------------------------------------------------------------------------

test('the skew badge and the AP verdict agree about the ±5 minute boundary', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');
  await runKerberos(page);

  const badge = page.locator('#clock-status');
  const slider = page.locator('#clock');
  await expect(page.locator('#clock-field')).toBeVisible();

  for (const [offset, tolerated] of [
    [0, true],
    [5, true],
    [-5, true],
    [6, false],
    [10, false],
    [-10, false],
  ] as const) {
    await slider.fill(String(offset));
    await slider.dispatchEvent('input');
    await expect(page.locator('#clock-value')).toHaveText(`${offset > 0 ? '+' : ''}${offset} min`);

    // The badge is a live prediction; the AP verdict is the real outcome.
    // They must not disagree — that is the whole self-teaching claim.
    await expect(badge).toHaveClass(new RegExp(`(^|\\s)${tolerated ? 'ok' : 'bad'}(\\s|$)`));
    await expect(badge).toHaveText(
      tolerated ? /within ±5 min tolerance/ : /SKEW — outside ±5 min, AP will reject/,
    );

    await expect(page.locator('#flow .flow-result').first()).toBeVisible({ timeout: HEAVY });
    await expect
      .poll(async () => (await results(page))[0]?.ok, { timeout: HEAVY })
      .toBe(tolerated);
    const [verdict] = await results(page);
    if (tolerated) {
      expect(verdict?.text).toContain('AP exchange accepted.');
    } else {
      expect(verdict?.text, `offset ${offset} rejected without a reason`).toContain(
        'AP exchange rejected: clock skew exceeded',
      );
      // A rejected AP leaves nothing to replay, so the panel goes away.
      await expect(page.locator('#replay-mount')).toBeHidden();
    }
  }
});

// ---------------------------------------------------------------------------
// The threat model — every glyph must match its own live result
// ---------------------------------------------------------------------------

test('every defense card’s glyph matches the live result printed under it', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');
  await runKerberos(page);

  const cards = await page.locator('#attacks-wrap .defense-card').evaluateAll((els) =>
    els.map((el) => ({
      label: el.querySelector('.defense-label')?.textContent?.trim() ?? '',
      tag: el.querySelector('.defense-tag')?.textContent?.trim() ?? '',
      glyph: el.querySelector('.defense-glyph')?.textContent?.trim() ?? '',
      sr: el.querySelector('.sr-only')?.textContent?.trim() ?? '',
      detail: el.querySelector('.defense-detail code')?.textContent?.trim() ?? '',
      ok: el.className.includes('ok'),
    })),
  );
  expect(cards).toHaveLength(9);
  await expect(page.locator('#attacks-wrap .defense-group-title')).toHaveText([
    'Replay',
    'Clock skew',
    'Ticket expiry',
    'Key theft & offline cracking',
    'The pre-Kerberos flaw',
  ]);

  // Glyph, tag, screen-reader text and CSS state are four renderings of one
  // boolean; every card must render all four the same way, and none may be
  // silent about what actually happened.
  for (const c of cards) {
    expect(c.glyph, c.label).toBe(c.ok ? '✓' : '✗');
    expect(c.tag, c.label).toBe(c.ok ? 'Defended' : 'Not defended');
    expect(c.sr, c.label).toBe(c.ok ? 'Defended:' : 'Not defended:');
    expect(c.detail.length, `${c.label} has no live result`).toBeGreaterThan(0);
  }

  // The cards partition into defended and honestly-undefended, and the lab is
  // honest about exactly which three are red.
  const red = cards.filter((c) => !c.ok).map((c) => c.label);
  expect(cards.filter((c) => c.ok).length + red.length).toBe(cards.length);
  expect(red).toHaveLength(3);

  const find = (needle: string): (typeof cards)[number] => {
    const c = cards.find((x) => x.label.toLowerCase().includes(needle));
    expect(c, `no card matching ${needle}`).toBeTruthy();
    return c!;
  };

  // Replay: the first authenticator is accepted, the identical resend is not.
  const first = find('first authenticator');
  expect(first.ok).toBe(true);
  expect(first.detail).toBe('fresh authenticator');
  const replayed = find('replayed authenticator');
  expect(replayed.ok).toBe(true);
  expect(replayed.detail).toBe('replay cache hit');

  // Skew and expiry fire, with the reason strings the defenses returned.
  expect(find('out-of-window timestamp').detail).toBe('clock skew exceeded');
  expect(find('ticket validity window').detail).toBe('ticket expired for client clock');

  // Pass-the-ticket is red on purpose: within the lifetime, possession works.
  const ptt = find('pass-the-ticket');
  expect(ptt.ok).toBe(false);
  expect(ptt.detail).toBe('ticket still valid for attacker use');

  // AS-REP roasting: the exhibit is that it succeeds. The dictionary hit is
  // the third of four candidates, so the guess count is the position, and the
  // cracked password is the one the account was registered with.
  const roast = find('as-rep roasting');
  expect(roast.ok).toBe(false);
  expect(roast.detail).toBe('AS-REP issued without PA-DATA, enc-part cracked offline after 3 guesses → "Summer2024!"');

  // The same request against a pre-auth account is refused before any
  // password-derived ciphertext exists to crack.
  const preauth = find('pre-auth required');
  expect(preauth.ok).toBe(true);
  expect(preauth.detail).toContain('PREAUTH_REQUIRED');

  // The pre-Kerberos flaw, and the patch — the same two runs the flow shows.
  const lowe = find('lowe man-in-the-middle');
  expect(lowe.ok).toBe(false);
  expect(lowe.detail).toBe('NS: Bob accepted forged run as Alice = true');

  const fixed = find('against lowe’s fix');
  expect(fixed.ok).toBe(true);
  expect(fixed.detail).toContain('identity mismatch: message 2 names "Bob", Alice called Mallory');
  expect(fixed.detail).toContain('Bob accepted = false');

  expect(red.sort()).toEqual([lowe.label, ptt.label, roast.label].sort());
});

test('the threat panel and the flow report the same Lowe outcomes', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');

  // Take the reason the lowe-fix flow computed…
  await selectScenario(page, 'lowe-fix');
  const flowReason = /Attack blocked at step 4 — ([^.]+)\./.exec((await results(page))[0]?.text ?? '')?.[1];
  expect(flowReason, 'the lowe-fix flow gave no reason').toBeTruthy();

  // …and require the threat panel's independent run to reach the same one.
  await runKerberos(page);
  const detail =
    (await page
      .locator('#attacks-wrap .defense-card', { hasText: 'against Lowe’s fix' })
      .locator('.defense-detail code')
      .textContent()) ?? '';
  expect(detail).toContain(flowReason!);
});

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

test('the timeline drives the scenario select, and each era renders its own panels', async ({ page }) => {
  test.setTimeout(HEAVY);
  await page.goto('.');

  const keys = await page.locator('#scenario option').evaluateAll((els) =>
    els.map((el) => (el as HTMLOptionElement).value),
  );
  expect(keys).toEqual(['ns', 'lowe-attack', 'lowe-fix', 'kerberos']);

  for (const key of keys) {
    await page.locator(`#timeline-mount li[data-key="${key}"] .timeline-step`).click();
    await expect(page.locator('#scenario')).toHaveValue(key);
    await expect(page.locator('#flow')).toHaveClass(new RegExp(`scenario-${key}(\\s|$)`));
    await expect(page.locator('#flow .flow-result').first()).toBeVisible({ timeout: HEAVY });

    // Tickets, replay, etype and threat panels belong to Kerberos alone.
    const kerberos = key === 'kerberos';
    for (const sel of ['#inspectors', '#etype-wrap', '#attacks-wrap', '#clock-field']) {
      if (kerberos) await expect(page.locator(sel)).toBeVisible({ timeout: HEAVY });
      else await expect(page.locator(sel)).toBeHidden();
    }
  }

  // The scope panel is always present — the lab states its limits everywhere.
  const scope = page.locator('#scope-panel');
  await expect(scope).toContainText('What this demo is, and is not');
  await expect(scope).toContainText('The cryptography below the protocol is real and vector-checked');
  // README: the limits are stated on screen, not only in the source.
  await expect(scope).toContainText('What this deliberately does NOT model');
  await expect(scope).toContainText('ASN.1/DER');
  await expect(scope).toContainText('One realm, no cross-realm');
  await expect(scope).toContainText('No PAC');
});
