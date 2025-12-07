// server.js
const express = require('express');
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,                 // max requests
  message: { error: "Too many requests, slow down." }
});
app.use(limiter); 

// Input validation

// Allowed pattern
const SAFE_FILENAME = /^[A-Za-z0-9._\-\/]+$/;

function sanitizeFilename(value) {
  if (!SAFE_FILENAME.test(value)) {
    throw new Error("Illegal characters in filename");
  }
  if (value.includes("..")) throw new Error("Path traversal attempt");
  if (value.startsWith("/")) throw new Error("Absolute paths not allowed");
  return value;
}

const BASE_DIR = path.resolve(__dirname, 'files');
if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });

function resolveSafe(baseDir, userInput) {
  try { userInput = decodeURIComponent(userInput); } catch (e) {}
  return path.resolve(baseDir, userInput);
}

// route

app.post(
  '/read',
  body('filename')
    .exists().withMessage('filename required')
    .bail()
    .isString()
    .trim()
    .notEmpty().withMessage('filename must not be empty')
    .custom(sanitizeFilename),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const filename = req.body.filename;
    const normalized = resolveSafe(BASE_DIR, filename);

    if (!normalized.startsWith(BASE_DIR + path.sep)) {
      return res.status(403).json({ error: 'Path traversal detected' });
    }
    if (!fs.existsSync(normalized)) return res.status(404).json({ error: 'File not found' });

    const content = fs.readFileSync(normalized, 'utf8');
    res.json({ path: normalized, content });
  }
);

// Vulnerable demo

app.post('/read-no-validate', (req, res) => {
  const filename = req.body.filename || '';
  const joined = path.join(BASE_DIR, filename); // intentionally vulnerable
  if (!fs.existsSync(joined)) return res.status(404).json({ error: 'File not found', path: joined });
  const content = fs.readFileSync(joined, 'utf8');
  res.json({ path: joined, content });
});

// helper route

app.post('/setup-sample', (req, res) => {
  const samples = {
    'hello.txt': 'Hello from safe file!\n',
    'notes/readme.md': '# Readme\nSample readme file'
  };
  Object.keys(samples).forEach(k => {
    const p = path.resolve(BASE_DIR, k);
    const d = path.dirname(p);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(p, samples[k], 'utf8');
  });
  res.json({ ok: true, base: BASE_DIR });
});

// run
if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

module.exports = app;
