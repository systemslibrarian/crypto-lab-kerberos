function line(label: string, value: string): string {
  return `<div class="ticket-line"><span>${label}</span><code>${value}</code></div>`;
}

export function renderTicketInspector(title: string, cipher: Uint8Array): string {
  const hex = Array.from(cipher)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  const first = hex.slice(0, 80);
  const rest = hex.slice(80);

  return `<section class="panel"><h3>${title}</h3>${line('etype', '18 (aes256-cts-hmac-sha1-96)')}${line('cipher (head)', first)}${line('cipher (tail)', rest || '(empty)')}</section>`;
}
