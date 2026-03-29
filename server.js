import express from 'express';
import { createHmac, pbkdf2Sync } from 'crypto';
import {
  initDb, setupEncryption, isFirstTime, addKey, getKeys, getKeyPrefs,
  deleteKey, rotateKey, updateKey, getHistory, exportAll, importKeys
} from './store.js';

const app = express();
app.use(express.json());
app.use(express.static('public'));

// Initialize database on startup
initDb();

// In-memory session: master password stored only in server memory while running
let masterPassword = null;

function requireAuth(req, res, next) {
  if (!masterPassword) {
    return res.status(401).json({ error: 'Not authenticated. Please unlock first.' });
  }
  next();
}

function generatePassword(basePassword, appKey, { length = 20, symbols = true, version = 1 } = {}) {
  const alpha = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const digits = '0123456789';
  const syms = '!@#$%&*-_=+?';
  const charset = alpha + digits + (symbols ? syms : '');
  const normalizedKey = appKey.toLowerCase().trim();

  const salt = `${normalizedKey}:v${version}`;
  const derived = pbkdf2Sync(basePassword, salt, 100000, 32, 'sha256');
  const hmac = createHmac('sha256', derived).update(salt).digest();
  const combined = Buffer.concat([derived, hmac]);

  let password = '';
  for (let i = 0; i < length; i++) {
    const val = (combined[i * 2 % combined.length] << 8) | combined[(i * 2 + 1) % combined.length];
    password += charset[val % charset.length];
  }

  const required = [alpha.slice(0, 26), alpha.slice(26), digits, ...(symbols ? [syms] : [])];
  required.forEach((set, idx) => {
    if (![...password].some(c => set.includes(c))) {
      const pos = idx % password.length;
      const replacement = set[combined[(idx + length) % combined.length] % set.length];
      password = password.slice(0, pos) + replacement + password.slice(pos + 1);
    }
  });

  return password;
}

// --- Auth ---
app.post('/api/unlock', (req, res) => {
  const { masterPw } = req.body;
  if (!masterPw) return res.status(400).json({ error: 'Master password required' });
  const result = setupEncryption(masterPw);
  if (!result.valid) return res.status(403).json({ error: 'Invalid master password' });
  masterPassword = masterPw;
  res.json({ success: true, firstTime: result.firstTime });
});

app.post('/api/lock', (_req, res) => {
  masterPassword = null;
  res.json({ success: true });
});

app.get('/api/status', (_req, res) => {
  res.json({ unlocked: !!masterPassword });
});

app.get('/api/first-time', (_req, res) => {
  res.json({ firstTime: isFirstTime() });
});

// --- Key operations ---
app.post('/api/generate', requireAuth, (req, res) => {
  const { basePassword, appKey, length, symbols, category } = req.body;
  if (!basePassword || !appKey) {
    return res.status(400).json({ error: 'basePassword and appKey are required' });
  }
  const key = appKey.toLowerCase().trim();
  const result = addKey(key, {
    length: length || 20,
    symbols: symbols !== false,
    category: category || '',
  }, masterPassword);

  if (!result.added) {
    return res.status(409).json({
      error: `App key "${key}" already exists.`,
      existing: result.prefs,
      duplicate: true,
    });
  }
  const password = generatePassword(basePassword, key, result.prefs);
  res.json({ password, appKey: key });
});

// Regenerate with different settings (for duplicate key flow)
app.post('/api/regenerate', requireAuth, (req, res) => {
  const { basePassword, appKey, length, symbols, category } = req.body;
  if (!basePassword || !appKey) {
    return res.status(400).json({ error: 'basePassword and appKey are required' });
  }
  const prefs = updateKey(appKey, {
    length: length || 20,
    symbols: symbols !== false,
    category: category || '',
  }, masterPassword);

  if (!prefs) return res.status(404).json({ error: 'Key not found' });
  const password = generatePassword(basePassword, appKey, prefs);
  res.json({ password, version: prefs.version });
});

app.post('/api/retrieve', requireAuth, (req, res) => {
  const { basePassword, appKey } = req.body;
  if (!basePassword || !appKey) {
    return res.status(400).json({ error: 'basePassword and appKey are required' });
  }
  const prefs = getKeyPrefs(appKey, masterPassword);
  if (!prefs) return res.status(404).json({ error: `App key "${appKey}" not found.` });
  const password = generatePassword(basePassword, appKey, prefs);
  res.json({ password });
});

app.get('/api/keys', requireAuth, (_req, res) => {
  res.json({ keys: getKeys(masterPassword) });
});

app.delete('/api/keys/:appKey', requireAuth, (req, res) => {
  const deleted = deleteKey(req.params.appKey);
  if (!deleted) return res.status(404).json({ error: 'Key not found' });
  res.json({ success: true });
});

app.post('/api/keys/:appKey/rotate', requireAuth, (req, res) => {
  const { basePassword } = req.body;
  if (!basePassword) return res.status(400).json({ error: 'basePassword is required' });
  const result = rotateKey(req.params.appKey);
  if (!result) return res.status(404).json({ error: 'Key not found' });
  const prefs = getKeyPrefs(req.params.appKey, masterPassword);
  const password = generatePassword(basePassword, req.params.appKey, prefs);
  res.json({ password, version: result.version });
});

app.get('/api/keys/:appKey/history', requireAuth, (req, res) => {
  const history = getHistory(req.params.appKey);
  res.json({ history });
});

app.get('/api/export', requireAuth, (_req, res) => {
  res.setHeader('Content-Disposition', 'attachment; filename="passgen-keys.json"');
  res.json(exportAll(masterPassword));
});

app.post('/api/import', requireAuth, (req, res) => {
  const count = importKeys(req.body, masterPassword);
  res.json({ imported: count });
});

const HOST = '0.0.0.0';
const PORT = process.env.PORT || 3000;
app.listen(PORT, HOST, () => console.log(`Server running at http://localhost:${PORT}`));
