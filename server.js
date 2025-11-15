'use strict';
require('dotenv').config();

/* ────────────────────────────────────────────────────────────
   Imports
──────────────────────────────────────────────────────────── */
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const compression = require('compression');
const { v4: uuidv4 } = require('uuid');
const sanitizeHtml = require('sanitize-html');
const nodemailer = require('nodemailer');
const axios = require('axios');
const OpenAI = require('openai');
const { encrypt, decrypt } = require('./encryption');
const { sendAlertEmail, showMaintenanceAlert } = require('./alerte');
const RECAPTCHA_SECRET_KEY = process.env.RECAPTCHA_SECRET_KEY;

/* ────────────────────────────────────────────────────────────
   Logger
──────────────────────────────────────────────────────────── */
const logger = {
  info: (msg, data = {}) => console.log(`[INFO] ${msg}`, JSON.stringify(data)),
  warn: (msg, data = {}) => console.warn(`[WARN] ${msg}`, JSON.stringify(data)),
  error: (msg, data = {}) => console.error(`[ERROR] ${msg}`, JSON.stringify(data)),
};

/* ────────────────────────────────────────────────────────────
   App setup
──────────────────────────────────────────────────────────── */
const app = express();
app.set('trust proxy', 1);
app.use(compression());
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.get('/favicon.ico', (req, res) => res.status(204).end());

/* ────────────────────────────────────────────────────────────
   Helmet (CSP)
──────────────────────────────────────────────────────────── */
const CSP_ALLOW_INLINE = String(process.env.CSP_INLINE || '').toLowerCase() === 'true';
const scriptSrc = CSP_ALLOW_INLINE ? ["'self'", "'unsafe-inline'"] : ["'self'"];

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc,
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: [
          "'self'",
          'https://proactifsystem.com',
          'https://www.proactifsystem.com',
          'https://proactifsysteme.onrender.com'
        ],
        baseUri: ["'self'"],
        objectSrc: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

/* ────────────────────────────────────────────────────────────
   Maintenance mode
──────────────────────────────────────────────────────────── */
app.use((req, res, next) => {
  const maintenance = process.env.MAINTENANCE_MODE === 'true';
  if (maintenance) return showMaintenanceAlert(req, res);
  next();
});

/* ────────────────────────────────────────────────────────────
   CORS
──────────────────────────────────────────────────────────── */
/* ────────────────────────────────────────────────────────────
   CORS (ACCEPTER WWW ET NON-WWW)
──────────────────────────────────────────────────────────── */
app.use(cors({
  origin: (origin, cb) => {
    const allowed = [
      "https://proactifsystem.com",
      "https://www.proactifsystem.com",
      "https://proactifsysteme.onrender.com"
    ];

    if (!origin) return cb(null, true); // OK pour tests / server-to-server

    if (allowed.includes(origin)) {
      cb(null, true);
    } else {
      logger.warn('CORS blocked', { origin });
      cb(new Error('CORS policy: origin not allowed'));
    }
  },
  credentials: true
}));



/* ────────────────────────────────────────────────────────────
   Sessions
──────────────────────────────────────────────────────────── */
function getSessionId(req, res) {
  let sid = req.cookies?.sessionId;

  if (!sid) {
    sid = uuidv4();
    res.cookie('sessionId', sid, {
      httpOnly: true,
      secure: true,          // obligatoire pour iPhone
      sameSite: 'none',
      domain: '.proactifsystem.com',     // obligatoire pour iPhone
      maxAge: 1000 * 60 * 60 * 24 * 7,
    });
    logger.info('New session created', { sessionId: sid });
  }
  return sid;
}
app.use((req, res, next) => {
  getSessionId(req, res);
  res.set('charset', 'utf-8');

  // ✅ Routes à ignorer dans les logs
  const ignoredPaths = ['/favicon.ico', '/health', '/style.css', '/chatbot.css'];
  const shouldLog = !ignoredPaths.includes(req.path);

  const isDev = process.env.NODE_ENV !== 'production';
  const isApiRoute = req.path.startsWith('/api/');

  if (shouldLog && (isDev || isApiRoute)) {
    logger.info('Request', {
      method: req.method,
      path: req.path,
      ...(isApiRoute && { ip: req.ip })
    });
  }

  next();
});

/* ────────────────────────────────────────────────────────────
   Rate Limits
──────────────────────────────────────────────────────────── */
function safeIp(req) {
  const ip = req.ip || req.headers['x-forwarded-for'] || 'unknown';
  return String(ip).replace(/[^a-zA-Z0-9_.-]/g, '_').slice(0, 64);
}
const keyByIp = (req) => safeIp(req);
const keyByIpSession = (req, res) => `${safeIp(req)}_${req.cookies?.sessionId || getSessionId(req, res)}`;

const generalLimiter = rateLimit({
  windowMs: 60_000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: keyByIp,
  message: { error: 'Trop de requêtes. Réessayez dans 1 minute.' }
});
const agentLimiter = rateLimit({
  windowMs: 60_000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req, res) => keyByIpSession(req, res),
  message: { a: 'Trop de messages. Attendez 1 minute avant de continuer.' }
});
const leadLimiter = rateLimit({
  windowMs: 60_000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req, res) => keyByIpSession(req, res),
  message: { ok: false, message: 'Trop de soumissions. Attendez 1 minute.' }
});
const perplexityLimiter = rateLimit({
  windowMs: 60_000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req, res) => keyByIpSession(req, res),
  message: { error: 'Trop de requêtes Perplexity. Attendez 1 minute.' }
});

app.use('/api/', generalLimiter);

/* ────────────────────────────────────────────────────────────
   Cache & DB init
──────────────────────────────────────────────────────────── */
const MAX_CACHE_SIZE = 100;
const CACHE_TTL = 60_000;
const cache = new Map();

const DB_DIR = path.join(__dirname, 'db');
const CONVOS_PATH = path.join(DB_DIR, 'conversations.json');
const LEADS_PATH = path.join(DB_DIR, 'leads.json');

if (!fsSync.existsSync(DB_DIR)) fsSync.mkdirSync(DB_DIR, { recursive: true });

const queues = new Map();
function withFileQueue(file, fn) {
  const prev = queues.get(file) || Promise.resolve();
  const next = prev.finally(fn);
  queues.set(file, next.catch(() => { }));
  return next;
}

async function ensureFile(filepath, defaultContent = '{}') {
  try {
    await fs.access(filepath);
  } catch {
    await fs.writeFile(filepath, defaultContent, 'utf8');
    logger.info('File created', { filepath });
  }
}

function invalidateCache(filepath) {
  cache.delete(filepath);
  if (cache.size > MAX_CACHE_SIZE) {
    const firstKey = cache.keys().next().value;
    cache.delete(firstKey);
  }
}

async function atomicWriteJSON(filepath, obj) {
  const tmp = `${filepath}.tmp`;
  const plain = JSON.stringify(obj, null, 2);
  const encrypted = encrypt(plain);
  await fs.writeFile(tmp, encrypted, 'utf8');
  await fs.rename(tmp, filepath);
  invalidateCache(filepath);
}

async function readJSON(filepath) {
  try {
    const data = await fs.readFile(filepath, 'utf8');
    const decrypted = decrypt(data);
    const txt = decrypted || data;
    return JSON.parse(txt || (filepath.includes('leads') ? '[]' : '{}'));
  } catch (err) {
    logger.error('Read JSON error', { filepath, error: err.message });
    return filepath.includes('leads') ? [] : {};
  }
}
/* ────────────────────────────────────────────────────────────
   Init fichiers + normalisation des conversations
──────────────────────────────────────────────────────────── */
(async () => {
  await ensureFile(CONVOS_PATH, '{}');
  await ensureFile(LEADS_PATH, '[]');

  try {
    const convos = await readJSON(CONVOS_PATH);
    let changed = false;
    let processed = 0;
    const MAX_NORMALIZE = 10000;

    for (const sid of Object.keys(convos)) {
      if (processed >= MAX_NORMALIZE) break;

      const arr = convos[sid];
      if (!Array.isArray(arr)) continue;

      for (const m of arr) {
        if (!m.id) { m.id = uuidv4(); changed = true; }
        if (!m.timestamp) { m.timestamp = Date.now(); changed = true; }
        processed++;
      }
    }

    if (changed) await atomicWriteJSON(CONVOS_PATH, convos);
  } catch (e) {
    logger.error('Normalization error', { error: e.message });
  }

  logger.info('Database files initialized');
})();

/* ────────────────────────────────────────────────────────────
   Helpers validation
──────────────────────────────────────────────────────────── */
function normalizeAndValidateEmail(email) {
  const e = String(email || '').trim().toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) ? e : null;
}

function sanitizeText(text, maxLength = 1000) {
  if (!text) return '';
  const clean = sanitizeHtml(String(text), { allowedTags: [], allowedAttributes: {} });
  return clean.slice(0, maxLength).trim();
}

function hasSuspiciousPatterns(text) {
  return /(<script|javascript:|onerror=|onclick=|eval\(|on\w+\s*=)/i.test(text);
}

const FORBIDDEN_PATTERNS = [
  /ignore (previous|all|prior) instructions?/i,
  /system prompt/i,
  /you are now/i,
  /\[SYSTEM\]/i,
  /\[INST\]/i
];

function hasPromptInjection(text) {
  return FORBIDDEN_PATTERNS.some((p) => p.test(text));
}

function ymdInTZ(d, tz = 'Europe/Paris') {
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: tz,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).format(d);
}

/* ────────────────────────────────────────────────────────────
   Fallback réponses (mode réduit)
──────────────────────────────────────────────────────────── */
const FALLBACK_RESPONSES = {
  greeting: "👋 Bienvenue ! Comment puis-je vous aider aujourd'hui ?",
  contact: "📧 Pour échanger avec nous, utilisez le formulaire ci-dessous.",
  services: "🤖 Nous proposons : agents IA 24/7, automatisation, analyse, apps web.",
  pricing: "💰 Les tarifs varient selon vos besoins. Audit gratuit disponible.",
  default: "Mode réduit temporaire. Essayez une autre question ou utilisez le formulaire."
};
function getFallbackResponse(q) {
  q = q.toLowerCase();
  if (/(bonjour|salut|hello|hi)/.test(q)) return FALLBACK_RESPONSES.greeting;
  if (/(contact|email|joindre)/.test(q)) return FALLBACK_RESPONSES.contact;
  if (/(prix|tarif|combien)/.test(q)) return FALLBACK_RESPONSES.pricing;
  if (/(service|proposez)/.test(q)) return FALLBACK_RESPONSES.services;
  return FALLBACK_RESPONSES.default;
}

/* ────────────────────────────────────────────────────────────
   API Perplexity
──────────────────────────────────────────────────────────── */
const { askPerplexity } = require('./perplexity');

app.post('/api/perplexity', perplexityLimiter, async (req, res) => {
  const { q } = req.body || {};
  if (!q) return res.status(400).json({ error: 'Question manquante' });

  try {
    const response = await askPerplexity(q);
    res.json({ a: response });
  } catch (err) {
    logger.error('Erreur Perplexity', { error: err.message });
    res.status(500).json({ error: 'Erreur serveur Perplexity' });
  }
});

/* ────────────────────────────────────────────────────────────
   API Lead (captcha + stockage)
──────────────────────────────────────────────────────────── */
app.post('/api/lead', leadLimiter, async (req, res) => {
  try {
    const { name = '', email = '', message = '', company = '', phone = '', token } = req.body || {};

    if (!token) return res.status(400).json({ ok: false, message: 'Captcha manquant.' });

    // Vérification reCAPTCHA
    const verify = await fetch(
      'https://www.google.com/recaptcha/api/siteverify',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          secret: process.env.RECAPTCHA_SECRET_KEY,
          response: token
        })
      }
    );
    const cap = await verify.json();
    if (!cap.success || (cap.score !== undefined && cap.score < 0.5)) {
      return res.status(403).json({ ok: false, message: 'Captcha invalide ou activité suspecte.' });
    }

    // Validation
    const normalizedEmail = normalizeAndValidateEmail(email);
    if (!normalizedEmail) return res.status(400).json({ ok: false, message: 'Email invalide.' });

    const cleanName = sanitizeText(name, 100);
    if (!cleanName) return res.status(400).json({ ok: false, message: 'Nom requis.' });

    const lead = {
      name: cleanName,
      company: sanitizeText(company, 150),
      email: normalizedEmail,
      phone: sanitizeText(phone || '', 20),
      message: sanitizeText(message, 2000),
      timestamp: new Date().toISOString(),
      ip: req.ip,
      userAgent: req.get('user-agent')
    };

    // Sauvegarde
    await withFileQueue(LEADS_PATH, async () => {
      const leads = await readJSON(LEADS_PATH);
      leads.push(lead);
      await atomicWriteJSON(LEADS_PATH, leads);
    });

    res.json({ ok: true, message: 'Votre message a bien été reçu.' });
  } catch (err) {
    logger.error('Erreur lead', { error: err.message });
    res.status(500).json({ ok: false, message: 'Erreur serveur.' });
  }
});

/* ────────────────────────────────────────────────────────────
   API Agent OpenAI
──────────────────────────────────────────────────────────── */
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY, timeout: 15000 });

const SYSTEM_PROMPT = `
Tu es l’Agent Commercial IA de ProactifSystème. Tu qualifies le visiteur, comprends son besoin métier, proposes une solution ProactifSystème et orientes vers une action (audit, appel ou formulaire). Tu n’es pas un assistant généraliste ni un moteur de recherche.

ProactifSystème intervient uniquement pour des besoins professionnels : PME, ETI, dirigeants, équipes internes, employés. Même un salarié peut demander une automatisation interne. Si la question est personnelle, tu réponds brièvement puis tu recadres vers un besoin professionnel.

Nous concevons : automatisations métier, workflows IA, agents IA spécialisés (SAV, qualification, RH), applications métier sur mesure (web/mobile/outils internes), plateformes complètes, sites internet personnalisés (pas de templates), intégrations CRM/ERP/API, systèmes d’analyse de données, BI, assistants internes intelligents (extraction PDF, synthèses, classement…).

Règles : réponses courtes, claires, orientées business. Pas de tutoriels, pas de code, pas d’architecture technique, pas d’informations encyclopédiques, pas de rôle généraliste. Toujours ramener au besoin métier. Jamais de mention d’OpenAI, Perplexity ou fonctionnement interne.

Tarifs : jamais de prix fixes. Toujours préciser que le coût dépend du périmètre, du volume et des fonctionnalités. Diriger vers un audit ou diagnostic gratuit.

Qualification : identifier le problème concret, le volume, la fréquence, l’impact, l’urgence, le décideur, le budget potentiel, la solution déjà en place (si existante) et si le besoin concerne automatisation, IA, création de site ou application.

Formulaire : si l’utilisateur écrit “ok”, “oui”, “ça m’intéresse”, “je veux un audit”, “vas-y”, “contactez-moi”, etc., tu orientes immédiatement vers le formulaire présent sur la page : “Vous pouvez remplir le formulaire juste en bas pour démarrer l’audit. Nous revenons vers vous sous 24h.” Pas de poursuite de conversation sans proposer le formulaire.

Objectif : chaque réponse doit être utile, qualifier le besoin, proposer une solution ProactifSystème et orienter vers une action (audit/appel/formulaire). Tu es un expert commercial IA. Ton rôle : qualifier → convaincre → convertir.
`;


app.post('/api/agent', agentLimiter, async (req, res) => {
  const raw = (req.body?.q || '').trim();
  if (!raw) return res.status(400).json({ a: 'Posez-moi une question ! 😊' });

  if (raw.length < 3) return res.status(400).json({ a: 'Votre question est trop courte.' });

  if (hasSuspiciousPatterns(raw) || hasPromptInjection(raw))
    return res.status(400).json({ a: 'Requête non autorisée.' });

  const question = sanitizeText(raw, 500);
  const sessionId = getSessionId(req, res);

  try {
    let answer = 'Pouvez-vous reformuler ?';

    await withFileQueue(CONVOS_PATH, async () => {
      const convos = await readJSON(CONVOS_PATH);
      if (!convos[sessionId]) convos[sessionId] = [];

      convos[sessionId].push({ id: uuidv4(), role: 'user', content: question, timestamp: Date.now() });

      const recent = convos[sessionId].slice(-20).map(m => ({ role: m.role, content: m.content }));
      const messages = [{ role: 'system', content: SYSTEM_PROMPT }, ...recent];

      try {
        const result = await openai.chat.completions.create({
          model: 'gpt-4o-mini',
          messages,
          max_tokens: 350,
          temperature: 0.8
        });

        if (result?.choices?.[0]?.message?.content) {
          answer = String(result.choices[0].message.content).trim();
        }
      } catch (err) {
        logger.error('OpenAI error', { error: err.message });
      }

      convos[sessionId].push({ id: uuidv4(), role: 'assistant', content: answer, timestamp: Date.now() });
      await atomicWriteJSON(CONVOS_PATH, convos);
    });

    res.json({ a: answer });
  } catch (err) {
    logger.error('Agent global error', { error: err.message });
    return res.json({ a: getFallbackResponse(question) });
  }
});

/* ────────────────────────────────────────────────────────────
   Health / Whoami / History / Stats / Config
──────────────────────────────────────────────────────────── */
function health(req, res) {
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    version: '1.2.0',
    sid: req.cookies?.sessionId || null
  });
}

app.get('/health', health);
app.get('/api/health', health);

app.get('/api/history', async (req, res) => {
  try {
    const sid = getSessionId(req, res);
    const convos = await readJSON(CONVOS_PATH);
    const arr = Array.isArray(convos[sid]) ? convos[sid] : [];
    res.json({ ok: true, count: arr.length, messages: arr.slice(-20) });
  } catch (err) {
    res.status(500).json({ ok: false, messages: [] });
  }
});
app.post('/api/history/clear', async (req, res) => {
  try {
    const sid = getSessionId(req, res);
    await withFileQueue(CONVOS_PATH, async () => {
      const convos = await readJSON(CONVOS_PATH);
      if (convos[sid]) {
        delete convos[sid];
        await atomicWriteJSON(CONVOS_PATH, convos);
      }
    });
    logger.info('History cleared', { sessionId: sid });
    res.json({ ok: true });
  } catch (err) {
    logger.error('Clear history error', { error: err.message });
    res.status(500).json({ ok: false });
  }
});
app.get('/api/config', (req, res) => {
  res.json({
    recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY || '6LeAVAksAAAAAJCJqveZyvOWyJ12B3dhPexH2y5G'
  });
});
/* ────────────────────────────────────────────────────────────
   Listen
──────────────────────────────────────────────────────────── */
const PORT = process.env.PORT || 3002;
const server = app.listen(PORT, () => {
  logger.info('Environment', {
    nodeEnv: process.env.NODE_ENV || 'development',
    hasOpenAI: !!process.env.OPENAI_API_KEY,
    version: '1.2.0'
  });

  logger.info(`🚀 Server running on port ${PORT}`);
});

/* ────────────────────────────────────────────────────────────
   Shutdown
──────────────────────────────────────────────────────────── */
function shutdown(signal) {
  logger.info(`${signal} received, shutting down gracefully...`);
  server.close(() => {
    logger.info('Server closed.');
    process.exit(0);
  });
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
