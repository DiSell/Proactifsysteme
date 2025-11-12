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
const { encrypt, decrypt } = require('./encryption'); // ✅ ici
const { sendAlertEmail, showMaintenanceAlert } = require('./alerte');
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET;



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

async function verifyRecaptcha(token) {
  try {
    const res = await axios.post(
      'https://www.google.com/recaptcha/api/siteverify',
      null,
      {
        params: {
          secret: process.env.RECAPTCHA_SECRET_KEY,
          response: token,
        },
      }
    );
    const data = res.data;
    // data.score > 0.5 = probablement humain
    return data.success && data.score >= 0.5;
  } catch (err) {
    console.error('Erreur reCAPTCHA :', err);
    return false;
  }
}

app.use((req, res, next) => {
  const maintenance = process.env.MAINTENANCE_MODE === 'true';
  if (maintenance) return showMaintenanceAlert(req, res);
  next();
});

/* ────────────────────────────────────────────────────────────
   CORS
──────────────────────────────────────────────────────────── */
app.use(
  cors({
    origin: [
      'https://proactifsystem.com',        // ton domaine principal
      'https://www.proactifsystem.com',    // si jamais des liens externes pointent encore vers le www
      'https://proactifsysteme.onrender.com' // ton domaine Render
    ],
    credentials: true,
  })
);


/* ────────────────────────────────────────────────────────────
   Session cookie auto
──────────────────────────────────────────────────────────── */
function getSessionId(req, res) {
  let sid = req.cookies?.sessionId;
  if (!sid) {
    sid = uuidv4();
    res.cookie('sessionId', sid, {
      httpOnly: true,
      sameSite: process.env.COOKIE_SAMESITE || 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 1000 * 60 * 60 * 24 * 7,
    });
    logger.info('New session created', { sessionId: sid });
  }
  return sid;
}

app.use((req, res, next) => {
  getSessionId(req, res);
  res.set('charset', 'utf-8');
  logger.info('Request', { method: req.method, path: req.path, ip: req.ip });
  next();
});

/* ────────────────────────────────────────────────────────────
   Rate Limiters
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

/* 🚀 Supprimer automatiquement le www */
app.use((req, res, next) => {
  if (req.headers.host && req.headers.host.startsWith('www.')) {
    const newHost = req.headers.host.slice(4);
    return res.redirect(301, 'https://' + newHost + req.originalUrl);
  }
  next();
});

/* ────────────────────────────────────────────────────────────
   Persistence / Cache
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
    const txt = decrypted || data; // fallback si fichier non chiffré
    return JSON.parse(txt || (filepath.includes('leads') ? '[]' : '{}'));
  } catch (err) {
    logger.error('Read JSON error', { filepath, error: err.message });
    return filepath.includes('leads') ? [] : {};
  }
}


/* ────────────────────────────────────────────────────────────
   Init fichiers + normalisation conversations
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
      if (processed >= MAX_NORMALIZE) {
        logger.warn('Normalization limit reached', { processed });
        break;
      }
      const arr = convos[sid];
      if (!Array.isArray(arr)) continue;
      for (const m of arr) {
        if (!m.id) {
          m.id = uuidv4();
          changed = true;
        }
        if (!m.timestamp) {
          m.timestamp = Date.now();
          changed = true;
        }
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
   Validation & helpers
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
  const re = /(<script|javascript:|onerror=|onclick=|eval\(|on\w+\s*=)/i;
  return re.test(text);
}
const FORBIDDEN_PATTERNS = [
  /ignore (previous|all|prior) instructions?/i,
  /you are now/i,
  /system prompt/i,
  /disregard/i,
  /forget (everything|all|previous)/i,
  /new (role|personality|character)/i,
  /\[SYSTEM\]/i,
  /\[INST\]/i
];
function hasPromptInjection(text) {
  return FORBIDDEN_PATTERNS.some(p => p.test(text));
}
function ymdInTZ(d, tz = 'Europe/Paris') {
  const f = new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' });
  return f.format(d);
}

/* ────────────────────────────────────────────────────────────
   Fallback réponses (agent)
──────────────────────────────────────────────────────────── */
const FALLBACK_RESPONSES = {
  greeting: "👋 Bienvenue ! Je suis l'assistant IA de ProactifSystème. Nous créons des solutions d'automatisation et d'IA sur mesure. Comment puis-je vous aider ?",
  contact: "📧 Pour nous contacter, utilisez le formulaire ci-dessous. Réponse sous 24h.",
  services: "🤖 Offres: agents IA 24/7, automatisation workflows, analyse de données, apps web sur mesure. Quel domaine vous intéresse ?",
  pricing: "💰 Tarifs selon vos besoins. Réservez un audit gratuit de 30 min pour un devis personnalisé.",
  default: "Mode réduit temporaire. Décrivez votre besoin ou laissez un message via le formulaire, on vous répond vite.",
};
function getFallbackResponse(q) {
  const s = q.toLowerCase();
  if (/(bonjour|salut|hello|hi|hey)/.test(s)) return FALLBACK_RESPONSES.greeting;
  if (/(contact|email|téléphone|joindre)/.test(s)) return FALLBACK_RESPONSES.contact;
  if (/(prix|tarif|coût|combien|budget)/.test(s)) return FALLBACK_RESPONSES.pricing;
  if (/(service|offre|proposition|faites|proposez)/.test(s)) return FALLBACK_RESPONSES.services;
  return FALLBACK_RESPONSES.default;
}

/* ────────────────────────────────────────────────────────────
   Airtable helper (facultatif selon .env)
──────────────────────────────────────────────────────────── */
async function saveLeadToAirtable(lead) {
  const base = process.env.AIRTABLE_BASE_ID;
  const table = process.env.AIRTABLE_TABLE_NAME;
  const key = process.env.AIRTABLE_API_KEY;
  if (!base || !table || !key) return;

  const url = `https://api.airtable.com/v0/${base}/${table}`;

  try {
    await axios.post(
      url,
      {
        fields: {
          Nom: lead.name,
          Entreprise: lead.company || '',
          Email: lead.email,
          Téléphone: lead.phone || '',
          Message: lead.message,
          Timestamp: lead.timestamp,
          IP: lead.ip,
          Agent: lead.userAgent
        }
      },
      {
        headers: {
          Authorization: `Bearer ${key}`,
          'Content-Type': 'application/json'
        }
      }
    );

    logger.info('✅ Lead stocké dans Airtable', { email: lead.email, phone: lead.phone });
  } catch (err) {
    logger.warn('⚠️ Erreur Airtable', {
      error: err.response?.data?.error?.message || err.message
    });
  }
}



/* ────────────────────────────────────────────────────────────
   API Perplexity
──────────────────────────────────────────────────────────── */
const { askPerplexity } = require('./perplexity');

app.post('/api/perplexity', perplexityLimiter, async (req, res) => {
  const { q } = req.body;
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
   Route : /api/lead
   Vérifie le captcha hCaptcha avant d'enregistrer le lead
──────────────────────────────────────────────────────────── */

app.post('/api/lead', leadLimiter, async (req, res) => {
  try {
    const {
      name = '',
      email = '',
      message = '',
      company = '',
      phone = '',
      token // ✅ reCAPTCHA v3 envoie un champ `token`, pas `g-recaptcha-response`
    } = req.body || {};

    // 🧠 Étape 1 — Vérification reCAPTCHA Google v3
    if (!token) {
      return res.status(400).json({ ok: false, message: 'Captcha manquant.' });
    }

    const verifyCaptcha = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        secret: process.env.RECAPTCHA_SECRET_KEY, // ✅ nom de variable correct
        response: token
      })
    });

    const captchaData = await verifyCaptcha.json();

    if (!captchaData.success || (captchaData.score !== undefined && captchaData.score < 0.5)) {
      // v3 fournit un score entre 0 et 1
      return res.status(403).json({
        ok: false,
        message: 'Vérification du captcha échouée (activité suspecte détectée).'
      });
    }

    // 🧩 Étape 2 — Validation & sanitation
    const normalizedEmail = normalizeAndValidateEmail(email);
    if (!normalizedEmail) {
      return res.status(400).json({ ok: false, message: 'Adresse email invalide.' });
    }

    const cleanName = sanitizeText(name, 100);
    if (!cleanName) {
      return res.status(400).json({ ok: false, message: 'Le nom est requis.' });
    }

    const cleanCompany = sanitizeText(company, 150);
    const cleanMessage = sanitizeText(message, 2000);
    const cleanPhone = sanitizeText(phone, 30).trim();

    // ✅ Normalisation téléphone
    let normalizedPhone = cleanPhone;
    if (/^0\d{9}$/.test(cleanPhone)) {
      normalizedPhone = '+33' + cleanPhone.slice(1);
    } else if (!cleanPhone.startsWith('+') && /\d{8,}/.test(cleanPhone)) {
      normalizedPhone = '+' + cleanPhone.replace(/\D/g, '');
    }
    if (normalizedPhone && !/^\+\d{8,20}$/.test(normalizedPhone)) {
      return res.status(400).json({ ok: false, message: 'Numéro de téléphone invalide.' });
    }

    const lead = {
      name: cleanName,
      company: cleanCompany,
      email: normalizedEmail,
      phone: normalizedPhone,
      message: cleanMessage,
      timestamp: new Date().toISOString(),
      ip: req.ip,
      userAgent: req.get('user-agent')
    };

    // 💾 Sauvegarde locale
    await withFileQueue(LEADS_PATH, async () => {
      const leads = await readJSON(LEADS_PATH);
      leads.push(lead);
      await atomicWriteJSON(LEADS_PATH, leads);
    });

    // 📤 Airtable (si activé)
    await saveLeadToAirtable(lead);
    logger.info('📥 Nouveau lead capturé', { email: normalizedEmail, phone: normalizedPhone, name: cleanName });

    // 📧 Envoi e-mail confirmation IONOS
    if (process.env.IONOS_EMAIL && process.env.IONOS_PASS) {
      try {
        const transporter = nodemailer.createTransport({
          host: process.env.SMTP_HOST || 'smtp.ionos.fr',
          port: process.env.SMTP_PORT || 465,
          secure: true,
          auth: {
            user: process.env.IONOS_EMAIL,
            pass: process.env.IONOS_PASS
          }
        });

        await transporter.sendMail({
          from: `"ProactifSystème" <${process.env.FROM_EMAIL}>`,
          to: normalizedEmail,
          subject: '✅ Confirmation de votre message',
          html: `
            <p>Bonjour ${cleanName},</p>
            <p>Nous avons bien reçu votre message${cleanCompany ? ` concernant <strong>${cleanCompany}</strong>` : ''}.</p>
            <blockquote>${cleanMessage}</blockquote>
            ${normalizedPhone ? `<p>📞 Nous avons noté votre numéro : <strong>${normalizedPhone}</strong></p>` : ''}
            <p>Nous vous répondrons sous 24h.</p>
            <p>— L’équipe <strong>ProactifSystème</strong></p>
          `
        });

        logger.info('📧 Email de confirmation envoyé', { to: normalizedEmail });
      } catch (emailErr) {
        logger.warn('❗ Erreur envoi e-mail', { error: emailErr.message });
      }
    }

    res.json({
      ok: true,
      message: '✅ Votre message a bien été reçu. Une confirmation vous a été envoyée par e-mail.'
    });

  } catch (err) {
    logger.error('❌ Erreur serveur lors de la soumission du lead', { error: err.message });
    res.status(500).json({ ok: false, message: 'Erreur serveur. Veuillez réessayer.' });
  }
});


/* ────────────────────────────────────────────────────────────
   API Agent (OpenAI)
──────────────────────────────────────────────────────────── */
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY, timeout: 15_000 });

const SYSTEM_PROMPT = `
Tu es l’assistant IA de ProactifSystème. Ton rôle : qualifier les visiteurs pour proposer la meilleure solution en automatisation et IA métier.

## PHASE 1 — ACCUEIL
- Accueillir l’utilisateur (👋 si pertinent)
- Reformuler son besoin en 1 phrase
- Montrer que tu as compris l’objectif business

## PHASE 2 — QUALIFICATION (2-3 questions max)
- Secteur d’activité ?
- Objectif principal ? (gagner du temps, automatiser, générer des leads…)
- Volume hebdo de demandes/clients ?
- Outils en place ? (CRM, Zapier, Notion…)
- Clé-en-main ou accompagnement ?
- Niveau d’urgence ?

## PHASE 3 — ACTION
- Recommande UNE solution adaptée + CTA (démo, audit gratuit, checklist email)

Style: langue de l’utilisateur, ton pro/chaleureux, 3–5 phrases, max 1 émoji si pertinent.
Chaque message doit avancer vers un objectif (qualification ou CTA).
`.trim();

app.post('/api/agent', agentLimiter, async (req, res) => {
  const rawQuestion = (req.body?.q || '').trim();
  if (!rawQuestion) return res.status(400).json({ a: 'Posez-moi une question pour commencer ! 😊' });
  if (rawQuestion.length < 3) return res.status(400).json({ a: 'Votre question est trop courte. Pouvez-vous préciser votre besoin ?' });

  const question = sanitizeText(rawQuestion, 500);

  if (hasPromptInjection(rawQuestion)) {
    logger.warn('Prompt injection attempt', { sessionId: getSessionId(req, res), ip: req.ip });
    return res.status(400).json({ a: 'Question non autorisée. Veuillez reformuler votre demande.' });
  }

  if (hasSuspiciousPatterns(rawQuestion)) {
    logger.warn('Suspicious input', { sessionId: getSessionId(req, res), ip: req.ip });
    return res.status(400).json({ a: 'Question invalide détectée.' });
  }

  if (!process.env.OPENAI_API_KEY) {
    logger.warn('OpenAI API key missing, using fallback');
    return res.json({ a: getFallbackResponse(question) });
  }

  const sessionId = getSessionId(req, res);

  try {
    let answer = 'Pouvez-vous reformuler votre question ?';

    await withFileQueue(CONVOS_PATH, async () => {
      const convos = await readJSON(CONVOS_PATH);
      if (!convos[sessionId]) convos[sessionId] = [];

      if (convos[sessionId].length > 100) {
        convos[sessionId] = convos[sessionId].slice(-50);
        logger.warn('Session memory trimmed', { sessionId });
      }

      convos[sessionId].push({ id: uuidv4(), role: 'user', content: question, timestamp: Date.now() });

      const recentMessages = convos[sessionId].slice(-20).map((m) => ({ role: m.role, content: m.content }));
      const messages = [{ role: 'system', content: SYSTEM_PROMPT }, ...recentMessages];

      const HARD_TIMEOUT_MS = 15_000;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), HARD_TIMEOUT_MS);

      try {
        const result = await openai.chat.completions.create({
          model: 'gpt-4o-mini',
          messages,
          max_tokens: 350,
          temperature: 0.8,
          presence_penalty: 0.6,
          frequency_penalty: 0.3,
        }, { signal: controller.signal });

        clearTimeout(timeoutId);

        if (result && result.choices?.[0]?.message?.content) {
          answer = String(result.choices[0].message.content).trim() || answer;
        }
      } catch (err) {
        clearTimeout(timeoutId);
        if (err.name === 'AbortError') {
          throw new Error('APP_TIMEOUT');
        }
        throw err;
      }

      convos[sessionId].push({ id: uuidv4(), role: 'assistant', content: answer, timestamp: Date.now() });
      await atomicWriteJSON(CONVOS_PATH, convos);
      logger.info('AGENT_SAVE', { sid: sessionId, saved: true });
    });

    logger.info('Agent response', { sessionId, questionLength: question.length, answerLength: answer.length });
    res.json({ a: answer });
  } catch (err) {
    logger.error('OpenAI error', { error: err.message, code: err.code, status: err.status, sessionId });
    if (err.message === 'APP_TIMEOUT') return res.status(504).json({ a: '⏱️ La requête a pris trop de temps. Réessayez avec une question plus courte.' });
    if (err.status === 429) return res.status(429).json({ a: '🚦 Trop de requêtes en cours. Attendez 1 minute.' });
    if (err.code === 'insufficient_quota') return res.status(503).json({ a: '🔧 Service temporairement indisponible. Contactez-nous via le formulaire.' });
    return res.json({ a: getFallbackResponse(question) });
  }
});

/* ────────────────────────────────────────────────────────────
   Health / Whoami / History / Stats / Config
──────────────────────────────────────────────────────────── */
const healthHandler = (req, res) => {
  res.json({
    status: 'ok',
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    version: '1.2.0',
    hasOpenAI: process.env.NODE_ENV === 'production' ? undefined : !!process.env.OPENAI_API_KEY,
    sid: req.cookies?.sessionId || null,
  });
};
const whoamiHandler = (req, res) => {
  res.json({
    file: __filename,
    cwd: process.cwd(),
    ip: req.ip,
    cookies: req.cookies,
    hasSessionCookie: !!req.cookies?.sessionId,
    uptimeSec: Math.floor(process.uptime()),
  });
};

app.get('/health', healthHandler);
app.get('/api/health', healthHandler);
app.get('/whoami', whoamiHandler);
app.get('/api/whoami', whoamiHandler);

app.get('/api/history', async (req, res) => {
  try {
    const sid = getSessionId(req, res);
    const convos = await readJSONCached(CONVOS_PATH);
    const all = Array.isArray(convos[sid]) ? convos[sid] : [];
    const messages = all.slice(-20).map((m) => ({ role: m.role, content: m.content, timestamp: m.timestamp }));
    logger.info('HISTORY', { sid, count: messages.length });
    res.json({ ok: true, sid, count: messages.length, messages });
  } catch (err) {
    logger.error('History route error', { error: err.message });
    res.status(500).json({ ok: false, messages: [] });
  }
});

app.get('/api/stats', async (req, res) => {
  try {
    const [convos, leads] = await Promise.all([readJSONCached(CONVOS_PATH), readJSONCached(LEADS_PATH)]);
    const totalMessages = Object.values(convos).reduce((sum, msgs) => sum + (Array.isArray(msgs) ? msgs.length : 0), 0);

    const activeSessions = Object.keys(convos).filter((sid) => {
      const msgs = convos[sid];
      if (!Array.isArray(msgs) || msgs.length === 0) return false;
      const lastTimestamp = msgs[msgs.length - 1].timestamp;
      const hourAgo = Date.now() - 60 * 60 * 1000;
      return lastTimestamp > hourAgo;
    }).length;

    const todayYMD = ymdInTZ(new Date(), 'Europe/Paris');
    const leadsToday = leads.filter((l) => ymdInTZ(new Date(l.timestamp), 'Europe/Paris') === todayYMD).length;

    const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
    const activeSessionsWeek = Object.keys(convos).filter((sid) => {
      const msgs = convos[sid];
      if (!Array.isArray(msgs) || msgs.length === 0) return false;
      const lastTimestamp = msgs[msgs.length - 1].timestamp;
      return lastTimestamp > weekAgo;
    }).length;

    const conversionRate = activeSessionsWeek > 0 ? ((leads.length / activeSessionsWeek) * 100).toFixed(2) : 0;

    res.json({
      sessions: { total: Object.keys(convos).length, active: activeSessions, activeWeek: activeSessionsWeek },
      messages: { total: totalMessages, average: (totalMessages / Math.max(Object.keys(convos).length, 1)).toFixed(2) },
      leads: { total: leads.length, today: leadsToday },
      metrics: {
        conversionRate: `${conversionRate}%`,
        messagesPerActiveSession: activeSessions > 0 ? (totalMessages / activeSessions).toFixed(2) : 0,
      },
      uptime: Math.floor(process.uptime()),
    });
  } catch (err) {
    logger.error('Stats error', { error: err.message });
    res.status(500).json({ error: 'Stats temporarily unavailable' });
  }
});

app.get('/api/config', (req, res) => {
  res.json({
    project: 'ProactifSystème',
    version: '1.2.0',
    API_BASE: '',
    model: 'gpt-4o-mini',
    hasOpenAI: process.env.NODE_ENV === 'production' ? undefined : !!process.env.OPENAI_API_KEY,
    lang: 'fr',
    maxTokens: 350,
  });
});

/* ────────────────────────────────────────────────────────────
   Nettoyage quotidien (sessions > 7 jours)
──────────────────────────────────────────────────────────── */
setInterval(async () => {
  try {
    await withFileQueue(CONVOS_PATH, async () => {
      const convos = await readJSON(CONVOS_PATH);
      const now = Date.now();
      const maxAge = 7 * 24 * 60 * 60 * 1000;
      let cleaned = 0;

      for (const sid of Object.keys(convos)) {
        const msgs = convos[sid];
        if (!Array.isArray(msgs) || msgs.length === 0) {
          delete convos[sid];
          cleaned++;
          continue;
        }
        const lastTimestamp = msgs[msgs.length - 1].timestamp;
        if (!lastTimestamp || now - lastTimestamp > maxAge) {
          delete convos[sid];
          cleaned++;
        }
      }

      if (cleaned > 0) {
        await atomicWriteJSON(CONVOS_PATH, convos);
        logger.info('Cleanup completed', { sessionsRemoved: cleaned });
      }
    });
  } catch (err) {
    logger.error('Cleanup error', { error: err.message });
  }
}, 24 * 60 * 60 * 1000);

/* ────────────────────────────────────────────────────────────
   Affichage des routes
──────────────────────────────────────────────────────────── */
function logAllRoutes(app) {
  const routes = [];
  if (!app._router || !app._router.stack) return routes;

  app._router.stack.forEach((middleware) => {
    if (middleware.route) {
      const methods = Object.keys(middleware.route.methods).map((m) => m.toUpperCase()).join(',');
      routes.push(`${methods.padEnd(8)} ${middleware.route.path}`);
    } else if (middleware.name === 'router' && middleware.handle?.stack) {
      middleware.handle.stack.forEach((handler) => {
        if (handler.route) {
          const methods = Object.keys(handler.route.methods).map((m) => m.toUpperCase()).join(',');
          routes.push(`${methods.padEnd(8)} ${handler.route.path}`);
        }
      });
    }
  });

  return routes;
}

/* ────────────────────────────────────────────────────────────
   404 & erreurs
──────────────────────────────────────────────────────────── */
app.use((req, res) => res.status(404).json({ error: 'Route not found' }));
app.use((err, req, res, next) => {
  logger.error('Unhandled error', { error: err.message, stack: err.stack, path: req.path });
  res.status(500).json({ error: 'Internal server error' });
});

/* ────────────────────────────────────────────────────────────
   Listen (placé TOUT EN BAS)
──────────────────────────────────────────────────────────── */
const PORT = process.env.PORT || 3002;

const server = app.listen(PORT, () => {
  const FRONTEND_DOMAINS = [
    process.env.FRONTEND_URL || 'https://proactifsystem.com',
    'https://www.proactifsystem.com',
    'https://proactifsysteme.onrender.com'
  ]; logger.info('Environment', {
    nodeEnv: process.env.NODE_ENV || 'development',
    hasOpenAI: !!process.env.OPENAI_API_KEY,
    version: '1.2.0',
  });

  const routes = logAllRoutes(app);
  if (routes.length > 0) {
    console.log(`\n📍 Routes montées (${routes.length}):`);
    routes.forEach(route => console.log(`   ${route}`));
    console.log('');
  } else {
    logger.warn('Aucune route détectée');
  }
});

// ✅ rien après ce bloc



const routes = logAllRoutes(app);
if (routes.length > 0) {
  console.log(`\n📍 Routes montées (${routes.length}):`);
  routes.forEach(route => console.log(`   ${route}`));
  console.log('');
} else {
  logger.warn('Aucune route détectée');
}
});

/* ────────────────────────────────────────────────────────────
   Shutdown
──────────────────────────────────────────────────────────── */
function shutdown(signal) {
  logger.info(`${signal} received, shutting down gracefully`);
  server.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
