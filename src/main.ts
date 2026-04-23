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
  applyThemeButtonState(root.classList.contains('light'));

  const toggle = document.getElementById('theme-toggle');
  if (!toggle) throw new Error('Missing theme toggle button');

  toggle.addEventListener('click', () => {
    const next = root.classList.contains('light') ? 'dark' : 'light';
    if (next === 'light') root.classList.add('light');
    else root.classList.remove('light');
    localStorage.setItem('theme', next);
    applyThemeButtonState(next === 'light');
  });
}

void bootstrap();
