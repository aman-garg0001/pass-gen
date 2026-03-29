import { randomBytes, createCipheriv, createDecipheriv, scryptSync } from 'crypto';

const ALGO = 'aes-256-gcm';

// Derive a 32-byte key from the master password using scrypt
function deriveKey(masterPassword) {
  // Fixed salt for deterministic key derivation from master password
  // This is acceptable since the master password itself provides entropy
  const salt = Buffer.from('passgen-encryption-salt-v1', 'utf-8');
  return scryptSync(masterPassword, salt, 32, { N: 16384, r: 8, p: 1 });
}

export function encrypt(plaintext, masterPassword) {
  const key = deriveKey(masterPassword);
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGO, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Format: iv:tag:ciphertext (all hex)
  return iv.toString('hex') + ':' + tag.toString('hex') + ':' + encrypted.toString('hex');
}

export function decrypt(encryptedStr, masterPassword) {
  const key = deriveKey(masterPassword);
  const [ivHex, tagHex, dataHex] = encryptedStr.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const encrypted = Buffer.from(dataHex, 'hex');
  const decipher = createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  return decipher.update(encrypted) + decipher.final('utf-8');
}
