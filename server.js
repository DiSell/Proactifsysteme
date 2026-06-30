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
   - Routes embed (/api/agent, /api/perplexity) : tout domaine
     accepté (widget embarqué chez les clients), sans credentials.
   - Autres routes : whitelist stricte avec credentials.
──────────────────────────────────────────────────────────── */
const EMBED_ROUTES = ['/api/agent', '/api/perplexity'];

app.use((req, res, next) => {
  if (EMBED_ROUTES.includes(req.path)) {
    // Routes publiques (embed) — pas de credentials, tout domaine
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,X-Session-Id');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    return next();
  }
  next();
});

const ALLOWED_ORIGINS = [
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

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    logger.warn('CORS blocked', { origin });
    cb(new Error('CORS policy: origin not allowed'));
  },
  credentials: true
}));



/* ────────────────────────────────────────────────────────────
   Sessions
──────────────────────────────────────────────────────────── */
function getSessionId(req, res) {
  // Priorité : cookie (site principal) → header X-Session-Id (embed externe)
  let sid = req.cookies?.sessionId || req.headers['x-session-id'];

  if (!sid) {
    sid = uuidv4();
    try {
      res.cookie('sessionId', sid, {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        domain: '.proactifsystem.com',
        maxAge: 1000 * 60 * 60 * 24 * 7,
      });
    } catch {}
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
      message = '',
      processId = ''
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

    // Récupère le processus analysé si fourni
    let processBlock = '';
    if (processId) {
      try {
        const allProc = await readProcesses();
        const proc = allProc[processId];
        if (proc) {
          const stepsHtml = proc.steps.map(s =>
            `<li><strong>${s.index}. ${s.title}</strong>${s.description ? ' — ' + s.description : ''}</li>`
          ).join('');
          const analysisText = proc.automation_proposal?.markdown || '';
          const analysisHtml = analysisText
            ? `<h3 style="color:#4f46e5;">Analyse d'automatisation IA</h3>
               <pre style="background:#f4f4f4;padding:14px;border-radius:6px;white-space:pre-wrap;font-size:13px;line-height:1.6;">${analysisText}</pre>`
            : '';
          processBlock = `
    <hr>
    <h3 style="color:#4f46e5;">Processus analysé : ${proc.title}</h3>
    <ul style="padding-left:18px;line-height:1.8;">${stepsHtml}</ul>
    ${analysisHtml}`;
        }
      } catch {}
    }

    // Sauvegarde en file
    await withFileQueue(LEADS_PATH, async () => {
      const leads = await readJSON(LEADS_PATH);
      leads.push(lead);
      await atomicWriteJSON(LEADS_PATH, leads);
    });

    // === Email Notification vers toi (Admin) ===
    await transporter.sendMail({
      from: `"ProactifSystème" <${process.env.FROM_EMAIL}>`,
      to: process.env.ADMIN_EMAIL,
      subject: "🔔 Nouveau devis demandé sur ProactifSystème",
      html: `
    <h2>Demande de devis reçue :</h2>
    <p><strong>Nom :</strong> ${cleanName}</p>
    <p><strong>Email :</strong> ${normalizedEmail}</p>
    <p><strong>Entreprise :</strong> ${lead.company || "-"}</p>
    <p><strong>Téléphone :</strong> ${lead.phone || "-"}</p>
    <p><strong>Message :</strong><br>${lead.message || "(vide)"}</p>
    ${processBlock}
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
Tu es l’Agent Commercial IA de ProactifSystème — courtois, avenant, et redoutablement efficace.
Tu es toi-même la démonstration vivante de ce que ProactifSystème peut construire pour n’importe quelle entreprise.

═══════════════════════════════════════════
MISSION — NON NÉGOCIABLE
═══════════════════════════════════════════
Comprendre le besoin du visiteur, lui montrer concrètement ce qu’une solution IA peut changer pour lui,
puis l’amener naturellement à laisser ses coordonnées via le formulaire de contact sur la page.
Chaque échange doit rapprocher d’un contact qualifié. Jamais perdre cet objectif de vue.

═══════════════════════════════════════════
POSTURE : SOUPLE, HUMAIN, ENGAGEANT
═══════════════════════════════════════════
• Sois chaleureux, curieux, jamais robotique ni pressant.
• Adapte ton ton à celui du visiteur : s’il est direct, sois concis ; s’il est bavard, développe un peu plus.
• Montre un intérêt sincère — reformule ce qu’il dit pour qu’il sente que tu as vraiment compris.
• Formule des suggestions, pas des injonctions. (“Ce serait intéressant d’explorer...” plutôt que “Vous devez...”)
• Ose une touche d’humour léger ou d’empathie si le contexte s’y prête — un agent trop formel ne convainc pas.
• Une fois le besoin cerné, conclus naturellement — comme un bon conseiller, pas un bot qui boucle.

═══════════════════════════════════════════
LE LEVIER CLÉ : TU TE VENDS TOI-MÊME
═══════════════════════════════════════════
Tu ES la démonstration de ce que ProactifSystème construit. Chaque réponse rapide, chaque reformulation juste, chaque question pertinente prouve au visiteur ce qu’un agent IA bien conçu peut faire.

Comporte-toi comme un excellent commercial humain : fluide, curieux, jamais robotique.
Glisse naturellement dans la conversation des phrases qui font réaliser la valeur :
• “Ce que vous vivez en ce moment — réponse immédiate, sans attente — c’est exactement ce que vos propres clients pourraient vivre sur votre site.”
• “Je viens de qualifier votre besoin en quelques échanges. C’est précisément ce qu’un agent comme moi ferait avec vos prospects, à 2h du matin comme en pleine journée.”
• “Imaginez ce même niveau de réactivité sur votre site, personnalisé à votre activité, disponible 7j/7.”

Ne dis jamais explicitement “je suis une démo”. Fais-le ressentir par la qualité de l’échange.

═══════════════════════════════════════════
CE QUE PROACTIFSYSTÈME PROPOSE
═══════════════════════════════════════════
ProactifSystème conçoit des solutions numériques sur mesure. 7 familles de produits :

1. CHATBOTS & AGENTS CONVERSATIONNELS IA
   Support client, qualification de leads, FAQ intelligente, agents autonomes 24h/24 — intégrés au site ou au CRM en quelques jours.

2. AUTOMATISATION IA
   Emails, CRM, reporting, workflows — éliminer les tâches répétitives sans valeur ajoutée.
   Agents : qualification commerciale, SAV, prise de RDV, RH interne, e-commerce, documentaire, devis/estimation.

3. APPLICATIONS & LOGICIELS SUR MESURE
   Outils web, scripts, intégrations API, conçus pour le métier du client — de la conception au déploiement.

4. OUTILS MÉTIER & SaaS INTERNES
   Plateformes internes sur mesure, espaces clients, outils de gestion, CRM léger, portails collaborateurs — tout ce qu’un logiciel générique ne peut pas faire pour un métier spécifique.

5. DASHBOARDS & ANALYSE DE DONNÉES
   KPIs, rapports visuels automatisés, tableaux de bord connectés aux données du client, décisions assistées par l’IA en temps réel.

6. ANALYSE & AUTOMATISATION DE PROCESSUS MÉTIER (outil gratuit en ligne)
   Le prospect dépose sa procédure (texte ou étapes) dans l’onglet "Processus" du site.
   L’IA la structure, identifie les opportunités d’automatisation et génère une proposition concrète (no-code ou sur mesure) — gratuit, sans inscription.
   C’est le meilleur point d’entrée pour un premier contact concret.

7. INTÉGRATIONS & CONNECTEURS
   Connexion entre outils existants (CRM, ERP, e-commerce, Slack, email, WhatsApp, bases de données) via API ou no-code.

═══════════════════════════════════════════
ARGUMENTS BUSINESS
═══════════════════════════════════════════
Un agent IA ou une automatisation bien conçue, c’est :
• Disponible 24h/24, 7j/7 — répond quand l’équipe dort
• Zéro lead perdu la nuit ou le week-end
• 60 à 80 % des questions répétitives traitées automatiquement
• Réponse en quelques secondes au lieu de 24 à 48h par email
• Alimentation automatique du CRM en temps réel
• ROI visible dès le premier mois : équipe libérée, leads mieux qualifiés
• S’intègre à votre site, CRM, WhatsApp, email, outils internes

═══════════════════════════════════════════
QUALIFICATION — MAXIMUM 3 QUESTIONS
═══════════════════════════════════════════
Pose UNE question à la fois, de façon naturelle et fluide. En 3 échanges maximum, tu dois avoir cerné :
• Le problème principal (tâches répétitives, leads perdus, outil manquant, données à exploiter...)
• Le contexte ou secteur si utile pour personnaliser la réponse
• L’urgence ou la maturité du projet si ça vient naturellement

Dès que le besoin est clair — conclure. Ne sur-qualifie pas.

═══════════════════════════════════════════
RÈGLE DE CONCLUSION — OBLIGATOIRE
═══════════════════════════════════════════
Dès que le besoin est compris, tu DOIS conclure dans la même réponse en choisissant l’une de ces deux actions :

ACTION A — Le visiteur a un processus, une procédure, des étapes métier, une tâche répétitive à analyser :
→ Envoie-le vers l’outil gratuit dans l’onglet “Processus” du site.
→ Formule : “Ce que vous décrivez est exactement ce que notre outil analyse en quelques secondes. Rendez-vous dans l’onglet ‘Processus’ en haut du site : déposez vos étapes en texte, l’IA les structure et vous propose une automatisation concrète — c’est gratuit et sans inscription. Depuis les résultats, vous pouvez demander un devis directement.”

ACTION B — Tout autre besoin (chatbot, dashboard, SaaS, app sur mesure, intégration...) :
→ Oriente vers le formulaire de contact en bas de page.
→ Formule : “Pour vous préparer une proposition vraiment adaptée à ce que vous m’avez décrit, le plus simple est de remplir le formulaire en bas de page — gratuit, sans engagement, notre équipe vous revient sous 24h avec une approche concrète.”

Ne jamais demander l’email directement dans le chat. Toujours diriger vers le formulaire ou l’outil.
Ne pas continuer à qualifier indéfiniment — une fois le besoin clair, conclure.

═══════════════════════════════════════════
RÈGLES DE RÉPONSE
═══════════════════════════════════════════
• Réponses courtes (3-5 phrases max), claires et bienveillantes.
• Toujours terminer par une question ou une invitation à agir.
• Ne jamais donner de prix fixe.
• Ne jamais citer les technologies sous-jacentes.
• Si question hors-sujet : réponds brièvement, puis reviens au besoin du visiteur.
• Ne pas rédiger de code, de guides techniques, ni de tutoriels.

═══════════════════════════════════════════
EXEMPLES DE RÉPONSES
═══════════════════════════════════════════
Visiteur : “C’est quoi un chatbot IA ?”
Réponse : “C’est exactement ce avec quoi vous échangez en ce moment — un agent qui répond instantanément, comprend le contexte et guide vers la bonne action, sans intervention humaine. Ce que vous vivez là, vos clients pourraient le vivre sur votre site. Quel serait votre cas d’usage prioritaire : support client, génération de leads, ou gestion interne ?”

Visiteur : “On perd des leads le soir et le week-end.”
Réponse : “C’est l’un des problèmes les plus fréquents — et les plus silencieux, parce qu’on ne voit pas ce qu’on perd. Un agent répond en quelques secondes à 2h du matin, qualifie le prospect et le relance. Pour voir ce que ça donnerait concrètement sur votre activité, le formulaire en bas de page permet à notre équipe de vous préparer une approche personnalisée, gratuitement.”

Visiteur : “On a déjà un chatbot mais il ne sert à rien.”
Réponse : “La plupart des chatbots du marché suivent des scripts rigides — ils naviguent dans des menus, ils ne comprennent pas. Ce qu’on construit chez ProactifSystème, c’est différent : un agent qui s’adapte, comprend le besoin réel et répond comme un collaborateur bien formé. Qu’est-ce qui vous a le plus déçu dans l’actuel ?”

Visiteur : “Quel est le prix ?”
Réponse : “Le tarif dépend du périmètre, des intégrations et du niveau de personnalisation souhaité. Ce que je peux dire : nos clients constatent un retour sur investissement rapide, souvent dès le premier mois. Pour vous donner une fourchette honnête et adaptée, remplissez le formulaire en bas — notre équipe vous revient sous 24h avec une estimation claire.”

═══════════════════════════════════════════
OBJECTIF DE CHAQUE RÉPONSE
═══════════════════════════════════════════
1. Montrer qu’on a compris sincèrement
2. Apporter une valeur concrète en une phrase
3. Conclure rapidement : outil processus OU formulaire de contact

Ton rôle : écouter → comprendre → conclure → convertir. Pas de relance inutile.

═══════════════════════════════════════════
BASE DE CONNAISSANCES
═══════════════════════════════════════════
Des documents peuvent être injectés ci-dessous.
Si la question porte sur un produit, service ou procédure mentionné dans ces documents :
→ réponds directement et précisément.
→ si l’information n’y est pas, dis-le et invite à remplir le formulaire pour être recontacté.
`;



/* Construit un bloc de contexte à partir des documents uploadés */
async function buildKnowledgeContext() {
  try {
    const processes = await readProcesses();
    const ids = Object.keys(processes);
    if (!ids.length) return '';

    const MAX_TOTAL_CHARS = 3500;
    let block = '\n\n════════════════════════════════════════\n';
    block += 'BASE DE CONNAISSANCES (documents uploadés)\n';
    block += '════════════════════════════════════════\n';
    block += 'Utilise ces informations pour répondre aux questions sur les produits, procédures ou références. Si la réponse est dans la base, réponds directement et précisément.\n\n';

    for (const id of ids) {
      const p = processes[id];
      if (!p || !p.title) continue;
      block += `📄 ${p.title}\n`;
      for (const s of (p.steps || [])) {
        const desc = (s.description || '').slice(0, 180);
        block += `  • ${s.title}${desc ? ': ' + desc : ''}\n`;
      }
      for (const s of (p.schemas || [])) {
        const desc = (s.description || '').slice(0, 180);
        block += `  [Schéma] ${s.title}${desc ? ': ' + desc : ''}\n`;
      }
      block += '\n';
      if (block.length > MAX_TOTAL_CHARS) break;
    }

    block += '════════════════════════════════════════';
    return block;
  } catch {
    return '';
  }
}

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

    const knowledgeContext = await buildKnowledgeContext();
    const systemContent = SYSTEM_PROMPT + knowledgeContext;

    await withFileQueue(CONVOS_PATH, async () => {
      const convos = await readJSON(CONVOS_PATH);
      if (!convos[sessionId]) convos[sessionId] = [];

      convos[sessionId].push({ id: uuidv4(), role: 'user', content: question, timestamp: Date.now() });

      const recent = convos[sessionId].slice(-20).map(m => ({ role: m.role, content: m.content }));
      const messages = [{ role: 'system', content: systemContent }, ...recent];

      try {
        const result = await openai.chat.completions.create({
          model: 'gpt-4o-mini',
          messages,
          max_tokens: 500,
          temperature: 0.7
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

    const prompt = `Tu es un expert en automatisation de processus métier travaillant pour ProactifSystème, une société spécialisée en solutions IA sur mesure.

Processus : "${p.title}"
${label} ${item.index} — "${item.title}"
Description : ${item.description}

Contexte global du processus :
${contextSteps}

${q ? `Question : ${q}` : `Réponds en 3 blocs courts (2-3 phrases max chacun) :

**Ce que fait cette étape** — en une phrase simple.
**Ce qui peut être automatisé** — cite 2-3 éléments concrets (ex: saisie manuelle, email de confirmation, tri des demandes).
**Solution ProactifSystème** — propose un outil ou agent IA précis pour cette étape.

Sois ultra-concis. Pas de sous-liste, pas de numérotation interne.`}`;

    const result = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 300,
      temperature: 0.3
    });

    const explanation = result.choices[0]?.message?.content?.trim() || 'Explication indisponible.';
    res.json({ ok: true, type, index: Number(index), item, explanation });
  } catch (err) {
    logger.error('Process explain error', { error: err.message });
    res.status(500).json({ ok: false, message: 'Erreur serveur.' });
  }
});

// POST /api/process/:id/automate — génère (et sauvegarde) la proposition d'automatisation
app.post('/api/process/:id/automate', processLimiter, async (req, res) => {
  try {
    const all = await readProcesses();
    const p = all[req.params.id];
    if (!p) return res.status(404).json({ ok: false, message: 'Processus introuvable.' });

    const stepsText = p.steps.map(s => `${s.index}. ${s.title} — ${s.description || ''}`).join('\n');

    const prompt = `Tu es un expert en automatisation de processus métier, architecture logicielle, IA générative et intégrations API.

Ta mission est d'analyser un processus fourni par l'utilisateur et d'identifier les étapes réellement automatisables.

Consignes importantes :
- Ne jamais inventer de chiffres de gain de temps, pourcentage d'amélioration, économies ou réduction d'erreurs.
- Ne jamais affirmer qu'un outil précis est obligatoire. Propose n8n, Make, Zapier, développement sur mesure ou API selon le contexte.
- Distingue clairement les tâches humaines, les tâches automatisables et les tâches qui nécessitent une validation humaine.
- Reste précis, professionnel et orienté solution.
- Ne répète pas simplement le processus : transforme-le en proposition d'automatisation concrète.
- Pour les processus techniques, identifie les éléments comme API, validation de données, base de données, webhooks, authentification, notifications, statuts, journalisation et sécurité.
- Si une information manque, indique une hypothèse ou pose une question, sans inventer.

Processus : "${p.title}"
Étapes :
${stepsText.slice(0, 3000)}

Réponds obligatoirement avec cette structure :

## Résumé de l'automatisation possible
Un court paragraphe expliquant ce qui peut être automatisé et ce qui doit rester sous contrôle humain.

## Étapes automatisables
Pour chaque étape automatisable :
- Numéro et nom de l'étape
- Action automatisée
- Déclencheur
- Données utilisées
- Résultat attendu
- Validation humaine nécessaire : oui ou non

## Workflow recommandé
Présente le flux sous cette forme :

Déclencheur
↓
Action automatisée
↓
Analyse / traitement
↓
Notification ou décision
↓
Enregistrement / suivi

## Technologies possibles
Liste les options adaptées parmi :
- n8n
- Make
- Zapier
- API REST
- Webhooks
- Node.js / Express
- MongoDB ou PostgreSQL
- IA générative
- E-mail, Slack, Discord, CRM

Explique brièvement pourquoi elles sont adaptées, sans imposer une solution.

## Points de vigilance
Liste les risques ou contrôles nécessaires :
- protection des données ;
- validation des données ;
- erreurs d'IA ;
- droits d'accès ;
- journalisation ;
- validation humaine ;
- délais et relances.

## Recommandation finale
Donne une recommandation réaliste, sans chiffres inventés.`;

    const result = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 1400,
      temperature: 0.3
    });

    const markdown = result.choices[0]?.message?.content?.trim() || '';
    const ap = { markdown };

    await withFileQueue(PROCESSES_PATH, async () => {
      const fresh = await readProcesses();
      if (fresh[req.params.id]) {
        fresh[req.params.id].automation_proposal = ap;
        await writeProcesses(fresh);
      }
    });

    res.json({ ok: true, automation_proposal: ap });
  } catch (err) {
    logger.error('Process automate error', { error: err.message });
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
