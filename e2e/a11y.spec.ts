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
