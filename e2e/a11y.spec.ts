import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the NIST/RFC KAT vectors;
 * this gates them on accessibility the same way. The lab is driven by a single
 * `#scenario` <select> that swaps in different panels (ticket inspectors, replay
 * controls, etype details, attack outcomes) per scenario, so we walk every
 * scenario, expand every collapsible, and scan in both themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

// Kill animations/transitions/opacity fades so axe reads final rendered colours.
const NEUTRALIZE_ANIM = `
  *, *::before, *::after {
    transition: none !important;
    animation: none !important;
    opacity: 1 !important;
  }
`;

async function revealEverything(page: Page): Promise<void> {
  // Expand every <details>.
  await page.evaluate(() => {
    for (const details of Array.from(document.querySelectorAll('details'))) {
      (details as HTMLDetailsElement).open = true;
    }
    // Reveal any class-hidden / [hidden] / display:none panels.
    for (const el of Array.from(document.querySelectorAll<HTMLElement>('.hidden, [hidden]'))) {
      el.classList.remove('hidden');
      el.removeAttribute('hidden');
      if (el.style.display === 'none') el.style.display = '';
    }
  });
}

async function scan(page: Page, context: string): Promise<void> {
  await revealEverything(page);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary, `violations in ${context}`).toEqual([]);
}

// Every scenario the select offers; scanned individually because each renders
// a different set of panels.
async function scenarioValues(page: Page): Promise<string[]> {
  return page.$$eval('#scenario option', (opts) =>
    opts.map((o) => (o as HTMLOptionElement).value),
  );
}

async function scanAllScenarios(page: Page, themeLabel: string): Promise<void> {
  const values = await scenarioValues(page);
  expect(values.length).toBeGreaterThan(0);
  for (const value of values) {
    await page.selectOption('#scenario', value);
    // Let the render settle.
    await page.locator('#flow').waitFor({ state: 'attached' });
    await scan(page, `${themeLabel} · scenario=${value}`);
  }
}

/**
 * WCAG 1.4.11 regression: text-entry control boundaries (input/textarea/select
 * borders) must hit >= 3:1 against at least one adjacent surface, after
 * compositing translucent colors over the real ancestor backgrounds.
 */
async function measureControlBorders(
  page: Page,
): Promise<Array<{ sel: string; best: number }>> {
  return page.evaluate(() => {
    const parse = (c: string): number[] => {
      const m = c.match(/rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)(?:[,\s/]+([\d.]+))?\s*\)/);
      return m ? [+m[1], +m[2], +m[3], m[4] === undefined ? 1 : +m[4]] : [0, 0, 0, 0];
    };
    const comp = (fg: number[], bg: number[]): number[] =>
      [0, 1, 2].map((i) => fg[i] * fg[3] + bg[i] * (1 - fg[3])).concat([1]);
    const lum = ([r, g, b]: number[]): number => {
      const f = (v: number) => {
        v /= 255;
        return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
    };
    const ratio = (a: number[], b: number[]): number => {
      const l1 = lum(a);
      const l2 = lum(b);
      return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
    };
    const effBg = (start: Element | null): number[] => {
      const stack: number[][] = [];
      let node: Element | null = start;
      while (node) {
        const c = parse(getComputedStyle(node).backgroundColor);
        if (c[3] > 0) stack.push(c);
        if (c[3] >= 1) break;
        node = node.parentElement;
      }
      let bg = [255, 255, 255, 1];
      for (let i = stack.length - 1; i >= 0; i--) bg = comp(stack[i], bg);
      return bg;
    };
    const TEXTY = ['', 'text', 'number', 'password', 'email', 'search', 'url', 'tel'];
    const out: Array<{ sel: string; best: number }> = [];
    document.querySelectorAll('input, textarea, select').forEach((el) => {
      if (el.tagName === 'INPUT' && !TEXTY.includes((el.getAttribute('type') || '').toLowerCase())) return;
      const cs = getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      if (cs.display === 'none' || cs.visibility === 'hidden' || rect.width === 0 || rect.height === 0) return;
      if ((parseFloat(cs.borderTopWidth) || 0) === 0) return;
      const outer = effBg(el.parentElement);
      const ownBg = parse(cs.backgroundColor);
      const inner = ownBg[3] >= 1 ? ownBg : comp(ownBg, outer);
      const borderRaw = parse(cs.borderTopColor);
      const best = Math.max(ratio(comp(borderRaw, outer), outer), ratio(comp(borderRaw, inner), inner));
      out.push({
        sel: el.tagName.toLowerCase() + (el.id ? '#' + el.id : ''),
        best: Math.round(best * 100) / 100,
      });
    });
    return out;
  });
}

for (const theme of ['dark', 'light'] as const) {
  test(`text control borders >= 3:1 in ${theme} theme`, async ({ page }) => {
    await page.goto('.');
    if (theme === 'light') {
      await page.locator('#cl-theme-toggle').click();
      await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    }
    const rows = await measureControlBorders(page);
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.filter((r) => r.best < 3)).toEqual([]);
  });
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await page.addStyleTag({ content: NEUTRALIZE_ANIM });
  await expect(page.locator('html')).not.toHaveAttribute('data-theme', 'light');
  await scanAllScenarios(page, 'dark');
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.addStyleTag({ content: NEUTRALIZE_ANIM });
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await scanAllScenarios(page, 'light');
});
