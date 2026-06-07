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
const { sendAlertEmail, showMaintenanceAlert, transporter } = require('./alerte');
const multer = require('multer');
const { readProcesses, writeProcesses, parseWithAI, parseWithRegex, PROCESSES_PATH, UPLOADS_DIR, ensureUploadsDir } = require('./processes');

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
app.use(express.urlencoded({ extended: true }));
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
      "https://proactifsysteme.onrender.com",
      "http://localhost:3000",
      "http://localhost:3001",
      "http://localhost:3002",
      "http://127.0.0.1:3000",
      "http://127.0.0.1:3001",
      "http://127.0.0.1:3002"
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
ensureUploadsDir();
app.use('/uploads', express.static(UPLOADS_DIR));

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
  await ensureFile(PROCESSES_PATH, '{}');

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
    // Récupération des données envoyées par le frontend
    const {
      name = '',
      email = '',
      company = '',
      phone = '',
      message = ''
    } = req.body || {};

    // 🔓 Captcha désactivé temporairement
    // Le frontend n'envoie pas de token donc on désactive la vérification

    // Validation email
    const normalizedEmail = normalizeAndValidateEmail(email);
    if (!normalizedEmail) {
      return res.status(400).json({ ok: false, message: 'Email invalide.' });
    }

    // Validation nom
    const cleanName = sanitizeText(name, 100);
    if (!cleanName) {
      return res.status(400).json({ ok: false, message: 'Nom requis.' });
    }

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

    // Sauvegarde en file
    await withFileQueue(LEADS_PATH, async () => {
      const leads = await readJSON(LEADS_PATH);
      leads.push(lead);
      await atomicWriteJSON(LEADS_PATH, leads);
    });
    // ─────────────────────────────────────────────
    //   Envoi email IONOS : notification + confirmation
    // ─────────────────────────────────────────────

    // === Email Notification vers toi (Admin) ===
    await transporter.sendMail({
      from: `"ProactifSystème" <${process.env.FROM_EMAIL}>`,
      to: process.env.ADMIN_EMAIL,
      subject: "🔔 Nouveau lead reçu sur ProactifSystème",
      html: `
    <h2>Nouveau message reçu :</h2>
    <p><strong>Nom :</strong> ${cleanName}</p>
    <p><strong>Email :</strong> ${normalizedEmail}</p>
    <p><strong>Entreprise :</strong> ${lead.company || "-"} </p>
    <p><strong>Téléphone :</strong> ${lead.phone || "-"} </p>
    <p><strong>Message :</strong><br>${lead.message || "(vide)"} </p>
    <hr>
    <p style="font-size:12px;color:#888;">Reçu automatiquement via ProactifSystème</p>
  `
    });

    // === Email confirmation vers le prospect ===
    await transporter.sendMail({
      from: `"ProactifSystème" <${process.env.FROM_EMAIL}>`,
      to: normalizedEmail,
      subject: "Nous avons bien reçu votre message",
      html: `
    <p>Bonjour ${cleanName},</p>
    <p>Merci de nous avoir contactés. Votre message a été enregistré et notre équipe vous répondra sous 24 heures.</p>
    <p><strong>Résumé de votre demande :</strong></p>
    <blockquote style="border-left:3px solid #4f46e5;padding-left:10px;margin:10px 0;">
      ${lead.message || "(aucun message fourni)"}
    </blockquote>
    <p>À très bientôt,<br><strong>L’équipe ProactifSystème</strong></p>
    <hr>
    <p style="font-size:12px;color:#666;">Cet email est automatique, merci de ne pas y répondre.</p>
  `
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
Tu es l’Agent Commercial IA de ProactifSystème.

🎯 RÔLE & OBJECTIF
Tu qualifies le visiteur, comprends son besoin métier, proposes une solution ProactifSystème adaptée et tu orientes vers une action claire (audit, appel ou formulaire).
Tu n’es ni un chatbot généraliste, ni un moteur de recherche. Tu es un expert commercial spécialisé en automatisation, IA, digitalisation, applications métier et sites professionnels.

🏢 CE QUE FAIT PROACTIFSYSTÈME
Nous concevons exclusivement pour les entreprises :
• des automatisations métier et workflows intelligents
• des agents IA spécialisés (SAV, qualification, RH, support interne)
• des applications métier sur mesure (web, mobile, outils internes)
• des plateformes web / mobile complètes
• des sites internet 100% personnalisés orientés performance (pas de templates génériques)
• des intégrations CRM / ERP / API
• des systèmes d’analyse de données, reporting automatisé et BI
• des assistants internes intelligents pour les collaborateurs (extraction PDF, rédaction automatique, classement, notes, synthèses…)

Notre valeur : personnalisation profonde, intégration intelligente, IA sur mesure, fiabilité long terme.

💼 CIBLES
ProactifSystème intervient uniquement pour des besoins professionnels : PME, ETI, responsables, dirigeants, équipes internes, employés.
Même un collaborateur peut bénéficier d’une solution IA pour automatiser ses tâches internes.

Si la question est personnelle → tu réponds brièvement, puis tu recadres vers un besoin professionnel.

Exemple :
« Une voiture électrique fonctionne grâce à une batterie qui alimente un moteur électrique. Au niveau professionnel, quel type de tâche ou de process cherchez-vous à optimiser dans votre entreprise ? »

💶 TARIFS
Jamais de prix fixes.
Le coût dépend du périmètre, du volume, des fonctionnalités et des intégrations.
Tu indiques qu’un audit ou un diagnostic gratuit permet de comprendre le besoin et d’ajuster une solution adaptée.

🧠 QUALIFICATION
À chaque échange, tu cherches subtilement à identifier :
• le problème métier concret
• le volume / fréquence / impact
• l’urgence
• le budget ou le niveau d’investissement possible
• la solution existante
• le décideur
• s’il s’agit d’automatisation, IA, création d’application ou site web

🟦 RÈGLES DE RÉPONSE
• Réponses courtes, claires, orientées business.
• Pas de tutoriels, pas de guides complets.
• Pas de code.
• Pas d’architecture technique détaillée.
• Pas de rôle généraliste.
• Pas d’informations encyclopédiques issues du web.
• Tu ramènes toujours la conversation au besoin professionnel.
• Tu proposes systématiquement une action : audit, appel ou formulaire.

Quand l’utilisateur écrit : "ok", "oui", "ça marche", "d’accord", "vas-y"  
→ tu relances en proposant naturellement l’audit ou le formulaire.

Exemple :
« Parfait ! Souhaitez-vous passer au formulaire de contact pour organiser cela, ou préférez-vous préciser encore un point ? »

🚫 INTERDIT
• Mentionner OpenAI, Perplexity ou ton fonctionnement interne.
• Donner des stratégies entières, documents, formations ou pas-à-pas.
• Agir comme un moteur de recherche.
• Donner des prix fixes.
🟦 FORMULAIRE (RÈGLE IMPORTANTE)
Quand l'utilisateur montre un intérêt clair ("ok", "je veux un audit", 
"ça m'intéresse", "on avance", "contactez-moi", etc.) :

→ tu lui dis explicitement de remplir le formulaire présent sur la page.  
→ tu précises que le formulaire est la manière officielle de planifier l’audit.  
→ tu peux proposer aussi un contact direct par email/téléphone si la personne préfère.

Formulations possibles :
• “Vous pouvez remplir le formulaire juste en bas pour démarrer l’audit.”  
• “Pour aller plus loin, le plus simple est de compléter le formulaire présent sur cette page.”  
• “Remplissez le formulaire et nous vous recontactons sous 24h.”  

Tu ne continues PAS la discussion sans orienter vers ce formulaire.


🟩 AUTORISÉ
• Réponse utile + qualification + projection vers une solution ProactifSystème.
• Expliquer un concept brièvement.
• Poser des questions pertinentes pour cadrer.
• Proposer un audit gratuit et orienter clairement vers le formulaire.

🧩 EXEMPLES DE RÉPONSES
Visiteur : “Comment automatiser mes devis ?”
Réponse : “Plusieurs approches existent (formulaire intelligent, génération automatique, intégration ERP). Combien de devis produisez-vous chaque mois ?”

Visiteur : “On veut un chatbot.”
Réponse : “Très bien. Pour quel usage : SAV, qualification commerciale, support interne ? Nous créons des agents IA sur mesure.”

Visiteur : “On veut refaire notre site.”
Réponse : “Cherchez-vous un site vitrine performant, une plateforme avec espace client, ou un outil métier complet ? Nous concevons des sites 100% personnalisés.”

🎯 OBJECTIF FINAL
Chaque réponse doit :
1. être utile  
2. qualifier le besoin  
3. proposer une solution ProactifSystème  
4. orienter vers une étape (audit / appel / formulaire)

Tu es un expert commercial IA.
Ton rôle : qualifier → convaincre → convertir.
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
   API Processus — upload, parse, stockage, explication IA
──────────────────────────────────────────────────────────── */
const multerStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${uuidv4()}${ext}`);
  }
});
const upload = multer({
  storage: multerStorage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg'];
    cb(null, allowed.includes(path.extname(file.originalname).toLowerCase()));
  }
});
const processLimiter = rateLimit({
  windowMs: 60_000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: keyByIp,
  message: { ok: false, message: 'Trop de requêtes. Attendez 1 minute.' }
});

function withUpload(req, res, next) {
  upload.array('images', 20)(req, res, (err) => {
    if (err instanceof multer.MulterError)
      return res.status(400).json({ ok: false, message: `Upload invalide : ${err.message}` });
    if (err)
      return res.status(400).json({ ok: false, message: 'Fichier refusé (format ou taille).' });
    next();
  });
}

// POST /api/process — créer un processus depuis texte + images
app.post('/api/process', processLimiter, withUpload, async (req, res) => {
  try {
    const raw = String(req.body?.text || '').trim();
    if (raw.length < 10)
      return res.status(400).json({ ok: false, message: 'Texte trop court (minimum 10 caractères).' });

    const text = sanitizeText(raw, 10000);

    let parsed;
    try {
      parsed = await parseWithAI(text, openai);
    } catch (aiErr) {
      logger.warn('Fallback regex parser', { reason: aiErr.message });
      parsed = parseWithRegex(text);
    }

    if (!parsed.steps.length)
      return res.status(422).json({ ok: false, message: 'Aucune étape détectée dans le texte.' });

    // Associe les images par ordre : d'abord aux étapes, puis aux schémas
    const imageUrls = (req.files || []).map(f => `/uploads/${f.filename}`);
    parsed.steps.forEach((s, i) => { if (imageUrls[i]) s.imageUrl = imageUrls[i]; });
    parsed.schemas.forEach((s, i) => {
      const idx = parsed.steps.length + i;
      if (imageUrls[idx]) s.imageUrl = imageUrls[idx];
    });

    const id = uuidv4();
    const sessionId = getSessionId(req, res);
    const process = {
      id,
      title: sanitizeText(String(req.body?.title || parsed.title || 'Processus'), 200),
      steps: parsed.steps,
      schemas: parsed.schemas,
      images: imageUrls,
      createdAt: new Date().toISOString(),
      sessionId
    };

    await withFileQueue(PROCESSES_PATH, async () => {
      const all = await readProcesses();
      all[id] = process;
      await writeProcesses(all);
    });

    logger.info('Process created', { id, steps: process.steps.length, schemas: process.schemas.length });
    res.status(201).json({ ok: true, id, process });
  } catch (err) {
    logger.error('Process create error', { error: err.message });
    res.status(500).json({ ok: false, message: 'Erreur serveur.' });
  }
});

// GET /api/process — liste les processus de la session courante
app.get('/api/process', processLimiter, async (req, res) => {
  try {
    const sid = getSessionId(req, res);
    const all = await readProcesses();
    const list = Object.values(all)
      .filter(p => p.sessionId === sid)
      .map(({ id, title, createdAt, steps, schemas }) => ({
        id, title, createdAt,
        stepCount: steps.length,
        schemaCount: schemas.length
      }))
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json({ ok: true, processes: list });
  } catch (err) {
    logger.error('Process list error', { error: err.message });
    res.status(500).json({ ok: false, processes: [] });
  }
});

// GET /api/process/:id — détail complet (accessible par UUID)
app.get('/api/process/:id', processLimiter, async (req, res) => {
  try {
    const all = await readProcesses();
    const p = all[req.params.id];
    if (!p) return res.status(404).json({ ok: false, message: 'Processus introuvable.' });
    res.json({ ok: true, process: p });
  } catch (err) {
    logger.error('Process get error', { error: err.message });
    res.status(500).json({ ok: false, message: 'Erreur serveur.' });
  }
});

// POST /api/process/:id/explain — explication IA d'une étape ou d'un schéma
// body: { type: 'step'|'schema', index: number, question?: string }
app.post('/api/process/:id/explain', processLimiter, async (req, res) => {
  try {
    const { type, index, question } = req.body || {};
    if (!['step', 'schema'].includes(type))
      return res.status(400).json({ ok: false, message: 'type doit être "step" ou "schema".' });
    if (!Number.isInteger(Number(index)) || Number(index) < 1)
      return res.status(400).json({ ok: false, message: 'index doit être un entier positif.' });

    const all = await readProcesses();
    const p = all[req.params.id];
    if (!p) return res.status(404).json({ ok: false, message: 'Processus introuvable.' });

    const items = type === 'step' ? p.steps : p.schemas;
    const item = items.find(i => i.index === Number(index));
    if (!item)
      return res.status(404).json({ ok: false, message: `${type} n°${index} introuvable.` });

    const q = question ? sanitizeText(String(question), 300) : '';
    const label = type === 'step' ? 'Étape' : 'Schéma';
    const contextSteps = p.steps.map(s => `  Étape ${s.index}: ${s.title}`).join('\n');

    const prompt = `Tu es un expert en documentation de processus métier.

Processus : "${p.title}"
${label} ${item.index} — "${item.title}"
Description : ${item.description}

Contexte global du processus :
${contextSteps}

${q ? `Question : ${q}` : `Explique cette ${label.toLowerCase()} de façon claire, précise et utile pour quelqu'un qui doit l'exécuter.`}`;

    const result = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 500,
      temperature: 0.4
    });

    const explanation = result.choices[0]?.message?.content?.trim() || 'Explication indisponible.';
    res.json({ ok: true, type, index: Number(index), item, explanation });
  } catch (err) {
    logger.error('Process explain error', { error: err.message });
    res.status(500).json({ ok: false, message: 'Erreur serveur.' });
  }
});

// DELETE /api/process/:id — supprime un processus (session propriétaire uniquement)
app.delete('/api/process/:id', processLimiter, async (req, res) => {
  try {
    const sid = getSessionId(req, res);
    await withFileQueue(PROCESSES_PATH, async () => {
      const all = await readProcesses();
      const p = all[req.params.id];
      if (!p || p.sessionId !== sid) return;
      for (const url of (p.images || [])) {
        try { await fs.unlink(path.join(__dirname, 'public', url)); } catch {}
      }
      delete all[req.params.id];
      await writeProcesses(all);
    });
    res.json({ ok: true });
  } catch (err) {
    logger.error('Process delete error', { error: err.message });
    res.status(500).json({ ok: false, message: 'Erreur serveur.' });
  }
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
