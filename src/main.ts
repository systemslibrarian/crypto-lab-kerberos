import './style.css';
import { renderApp } from './app';

function applyThemeButtonState(isLight: boolean): void {
  const button = document.getElementById('theme-toggle');
  if (!button) return;
  button.textContent = isLight ? '\u263E' : '\u2600';
  button.setAttribute('aria-label', isLight ? 'Switch to dark mode' : 'Switch to light mode');
}

async function bootstrap(): Promise<void> {
  const app = document.querySelector<HTMLElement>('#app');
  if (!app) throw new Error('Missing #app mount point');

  await renderApp(app);

  const root = document.documentElement;
  const isLight = (): boolean => root.getAttribute('data-theme') === 'light';
  applyThemeButtonState(isLight());

  const toggle = document.getElementById('theme-toggle');
  if (!toggle) return;

  toggle.addEventListener('click', () => {
    const next = isLight() ? 'dark' : 'light';
    root.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    applyThemeButtonState(next === 'light');
  });
}

void bootstrap();
