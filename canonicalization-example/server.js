// server.js
const express = require('express');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');

const app = express();

// ============================================
// SECURITY FIX: Disable X-Powered-By header
// ============================================
app. disable('x-powered-by');

app.use(express. urlencoded({ extended: false }));
app.use(express.json());

// ============================================
// SECURITY FIX: Add security headers middleware
// ============================================
app.use((req, res, next) => {
  // Content Security Policy with frame-ancestors and form-action
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'"
  );
  
  // Permissions Policy
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=()'
  );
  
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  
  // XSS Protection
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // Cache Control - prevent caching of sensitive data
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  
  next();
});

app.use(express. static(path.join(__dirname, 'public')));

const BASE_DIR = path.resolve(__dirname, 'files');
if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });

// helper to canonicalize and check
function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {}
  return path.resolve(baseDir, userInput);
}

// Secure route
app.post(
  '/read',
  body('filename')
    .exists(). withMessage('filename required')
    .bail()
    .isString()
    .trim()
    .notEmpty().withMessage('filename must not be empty')
    .custom(value => {
      if (value.includes('\0')) throw new Error('null byte not allowed');
      return true;
    }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const filename = req.body. filename;
    const normalized = resolveSafe(BASE_DIR, filename);
    if (! normalized.startsWith(BASE_DIR + path.sep)) {
      return res.status(403).json({ error: 'Path traversal detected' });
    }
    if (!fs.existsSync(normalized)) return res.status(404).json({ error: 'File not found' });

    const content = fs. readFileSync(normalized, 'utf8');
    res. json({ path: normalized, content });
  }
);

// ============================================
// SECURITY FIX: Previously vulnerable route - now secured
// Fixed path traversal vulnerability
// ============================================
app. post('/read-no-validate', (req, res) => {
  const filename = req.body.filename || '';
  
  // FIX: Canonicalize and validate the path (same as secure route)
  const normalized = resolveSafe(BASE_DIR, filename);
  if (! normalized.startsWith(BASE_DIR + path.sep)) {
    return res.status(403). json({ error: 'Path traversal detected' });
  }
  
  if (!fs.existsSync(normalized)) {
    return res. status(404).json({ error: 'File not found' });
  }
  
  const content = fs.readFileSync(normalized, 'utf8');
  res.json({ path: normalized, content });
});

// Helper route for samples
app.post('/setup-sample', (req, res) => {
  const samples = {
    'hello. txt': 'Hello from safe file!\n',
    'notes/readme.md': '# Readme\nSample readme file'
  };
  Object.keys(samples).forEach(k => {
    const p = path.resolve(BASE_DIR, k);
    const d = path.dirname(p);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(p, samples[k], 'utf8');
  });
  res. json({ ok: true, base: BASE_DIR });
});

// Only listen when run directly (not when imported by tests)
if (require.main === module) {
  const port = process. env.PORT || 4000;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

module.exports = app;
