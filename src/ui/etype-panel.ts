import { decryptAes256CtsHmacSha196, deriveKeKi, encryptAes256CtsHmacSha196 } from '../crypto/etype-aes256';
import { hex, utf8Bytes } from '../crypto/simplified-profile';

export async function renderETypePanel(baseKey: Uint8Array): Promise<string> {
  const usage = 11;
  const plaintext = utf8Bytes('Kerberos etype panel vector mode');
  const enc = await encryptAes256CtsHmacSha196(baseKey, usage, plaintext);
  const dec = await decryptAes256CtsHmacSha196(baseKey, usage, enc.raw);
  const keys = await deriveKeKi(baseKey, usage);

  return `<section class="panel"><h3>Etype 18 Derivation</h3>
  <div class="ticket-line"><span>usage</span><code>${usage}</code></div>
  <div class="ticket-line"><span>Ke</span><code>${hex(keys.ke)}</code></div>
  <div class="ticket-line"><span>Ki</span><code>${hex(keys.ki)}</code></div>
  <div class="ticket-line"><span>ciphertext</span><code>${hex(enc.raw)}</code></div>
  <div class="ticket-line"><span>decrypt ok</span><code>${hex(dec) === hex(plaintext) ? 'true' : 'false'}</code></div>
  </section>`;
}
