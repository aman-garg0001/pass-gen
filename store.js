import Database from 'better-sqlite3';
import { encrypt, decrypt } from './crypto-utils.js';

const DB_FILE = process.env.DB_PATH || 'passgen.db';
let db;

export function initDb() {
  db = new Database(DB_FILE);
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS keys (
      app_key TEXT PRIMARY KEY,
      length INTEGER NOT NULL,
      symbols INTEGER NOT NULL,
      category TEXT DEFAULT '',
      version INTEGER DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      app_key TEXT NOT NULL,
      action TEXT NOT NULL,
      old_version INTEGER,
      new_version INTEGER,
      timestamp TEXT NOT NULL,
      details TEXT DEFAULT '',
      FOREIGN KEY (app_key) REFERENCES keys(app_key) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS encryption_check (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      token TEXT NOT NULL
    );
  `);
  return db;
}

// --- Encryption at rest ---
const ENCRYPTION_MARKER = 'passgen-valid';

export function isFirstTime() {
  const row = db.prepare('SELECT COUNT(*) as cnt FROM encryption_check').get();
  return row.cnt === 0;
}

export function setupEncryption(masterPassword) {
  const row = db.prepare('SELECT token FROM encryption_check WHERE id = 1').get();
  if (!row) {
    // First time — store encrypted marker
    const token = encrypt(ENCRYPTION_MARKER, masterPassword);
    db.prepare('INSERT INTO encryption_check (id, token) VALUES (1, ?)').run(token);
    return { valid: true, firstTime: true };
  }
  // Verify master password
  try {
    const decrypted = decrypt(row.token, masterPassword);
    return { valid: decrypted === ENCRYPTION_MARKER, firstTime: false };
  } catch {
    return { valid: false, firstTime: false };
  }
}

function encryptField(value, masterPassword) {
  return encrypt(String(value), masterPassword);
}

function decryptField(value, masterPassword) {
  return decrypt(value, masterPassword);
}

// --- Key operations ---
export function addKey(appKey, { length, symbols, category }, masterPassword) {
  const existing = db.prepare('SELECT app_key FROM keys WHERE app_key = ?').get(appKey);
  if (existing) {
    const prefs = getKeyPrefs(appKey, masterPassword);
    return { added: false, prefs };
  }

  const now = new Date().toISOString();
  const encCategory = encryptField(category || '', masterPassword);

  db.prepare(`
    INSERT INTO keys (app_key, length, symbols, category, version, created_at, updated_at)
    VALUES (?, ?, ?, ?, 1, ?, ?)
  `).run(appKey, length, symbols ? 1 : 0, encCategory, now, now);

  db.prepare(`
    INSERT INTO history (app_key, action, old_version, new_version, timestamp, details)
    VALUES (?, 'created', NULL, 1, ?, ?)
  `).run(appKey, now, `Length: ${length}, Symbols: ${symbols}, Category: ${category || 'none'}`);

  return { added: true, prefs: { length, symbols, category: category || '', version: 1, created_at: now, updated_at: now } };
}

export function getKeys(masterPassword) {
  const rows = db.prepare('SELECT * FROM keys ORDER BY app_key').all();
  const result = {};
  for (const row of rows) {
    result[row.app_key] = {
      length: row.length,
      symbols: !!row.symbols,
      category: decryptField(row.category, masterPassword),
      version: row.version,
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  }
  return result;
}

export function getKeyPrefs(appKey, masterPassword) {
  const row = db.prepare('SELECT * FROM keys WHERE app_key = ?').get(appKey);
  if (!row) return null;
  return {
    length: row.length,
    symbols: !!row.symbols,
    category: decryptField(row.category, masterPassword),
    version: row.version,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

export function deleteKey(appKey) {
  const result = db.prepare('DELETE FROM keys WHERE app_key = ?').run(appKey);
  db.prepare('DELETE FROM history WHERE app_key = ?').run(appKey);
  return result.changes > 0;
}

export function rotateKey(appKey) {
  const row = db.prepare('SELECT version FROM keys WHERE app_key = ?').get(appKey);
  if (!row) return null;
  const newVersion = row.version + 1;
  const now = new Date().toISOString();
  db.prepare('UPDATE keys SET version = ?, updated_at = ? WHERE app_key = ?').run(newVersion, now, appKey);

  db.prepare(`
    INSERT INTO history (app_key, action, old_version, new_version, timestamp)
    VALUES (?, 'rotated', ?, ?, ?)
  `).run(appKey, row.version, newVersion, now);

  return { version: newVersion };
}

export function updateKey(appKey, { length, symbols, category }, masterPassword) {
  const row = db.prepare('SELECT * FROM keys WHERE app_key = ?').get(appKey);
  if (!row) return null;
  const now = new Date().toISOString();
  const newVersion = row.version + 1;
  const encCategory = encryptField(category || '', masterPassword);

  db.prepare(`
    UPDATE keys SET length = ?, symbols = ?, category = ?, version = ?, updated_at = ?
    WHERE app_key = ?
  `).run(length, symbols ? 1 : 0, encCategory, newVersion, now, appKey);

  db.prepare(`
    INSERT INTO history (app_key, action, old_version, new_version, timestamp, details)
    VALUES (?, 'regenerated', ?, ?, ?, ?)
  `).run(appKey, row.version, newVersion, now,
    `Length: ${length}, Symbols: ${symbols}, Category: ${category || 'none'}`);

  return { length, symbols, category: category || '', version: newVersion, updated_at: now };
}

export function getHistory(appKey) {
  return db.prepare('SELECT * FROM history WHERE app_key = ? ORDER BY timestamp DESC').all(appKey);
}

export function exportAll(masterPassword) {
  return getKeys(masterPassword);
}

export function importKeys(incoming, masterPassword) {
  let count = 0;
  for (const [key, prefs] of Object.entries(incoming)) {
    const existing = db.prepare('SELECT app_key FROM keys WHERE app_key = ?').get(key);
    if (!existing) {
      addKey(key, {
        length: prefs.length || 20,
        symbols: prefs.symbols !== false,
        category: prefs.category || '',
      }, masterPassword);
      count++;
    }
  }
  return count;
}
