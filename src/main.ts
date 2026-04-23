import './style.css';
import { renderApp } from './app';

function applyThemeButtonState(theme: 'dark' | 'light'): void {
  const button = document.getElementById('theme-toggle');
  if (!button) {
    return;
  }
  button.textContent = theme === 'dark' ? '🌙' : '☀️';
  button.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
}

async function bootstrap(): Promise<void> {
  const app = document.querySelector<HTMLDivElement>('#app');
  if (!app) {
    throw new Error('Missing #app mount point');
  }

  await renderApp(app);

  const root = document.documentElement;
  const currentTheme = (root.getAttribute('data-theme') ?? 'dark') as 'dark' | 'light';
  applyThemeButtonState(currentTheme);

  const toggle = document.getElementById('theme-toggle');
  if (!toggle) {
    throw new Error('Missing theme toggle button');
  }

  toggle.addEventListener('click', () => {
    const active = (root.getAttribute('data-theme') ?? 'dark') as 'dark' | 'light';
    const next = active === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    applyThemeButtonState(next);
  });
}

void bootstrap();
