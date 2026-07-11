import { defineConfig } from 'vitest/config';

export default defineConfig({
  base: '/crypto-lab-kerberos/',
  test: {
    // Only run Vitest unit tests. The Playwright e2e specs (e2e/) must not be
    // collected by Vitest, or they throw "test() was not expected here".
    include: ['test/**/*.test.ts'],
  },
});
