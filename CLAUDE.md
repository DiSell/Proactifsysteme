# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commandes essentielles

```bash
# Installer les dépendances
npm install

# Démarrer en développement (avec rechargement automatique)
npm run dev

# Démarrer en production
npm start
```

Il n'y a pas de suite de tests — les validations se font via les endpoints API manuellement ou en déployant sur Render.

## Architecture

Application Node.js monofichier avec un frontend statique servi par Express.

### Backend — `server.js`
Point d'entrée unique qui orchestre tout :
- **Sessions** : cookie `sessionId` (UUID) géré par `getSessionId()`, transmis à chaque requête
- **File d'écriture** : `withFileQueue(file, fn)` sérialise tous les accès disque pour éviter les corruptions concurrentes sur `db/conversations.json` et `db/leads.json`
- **Chiffrement** : toutes les écritures passent par `atomicWriteJSON()` (chiffré via `encryption.js`) et toutes les lectures par `readJSON()` (déchiffré)
- **Choix du moteur IA** : fait côté client dans `public/js/agent.js` → `detectEngine()` route vers `/api/agent` (OpenAI) ou `/api/perplexity` selon des mots-clés

### Modules auxiliaires
| Fichier | Rôle |
|---|---|
| `encryption.js` | AES-256-CBC — chiffre/déchiffre les fichiers `db/` |
| `alerte.js` | Transporter nodemailer IONOS partagé + page de maintenance 503 |
| `perplexity.js` | Wrapper axios vers l'API Perplexity |
| `cleanup.js` | Script standalone (non importé) — à appeler manuellement pour purger les leads > 1 an |

### Frontend — `public/`
- `index.html` : page unique (hero + bento solutions + formulaire lead + widget chatbot)
- `public/js/agent.js` : toute la logique UI du chatbot (envoi messages, FAQ, formulaire lead, reconnaissance vocale, historique)
- `public/js/config.js` : expose `window.API_BASE_URL` (URL du serveur Render)
- `public/style.css` : styles de la page principale
- `public/chatbot.css` : styles du widget chatbot flottant

### Endpoints API
| Route | Limiteur | Description |
|---|---|---|
| `POST /api/agent` | 10 req/min par IP+session | Chat OpenAI gpt-4o-mini |
| `POST /api/perplexity` | 5 req/min par IP+session | Recherche web via Perplexity |
| `POST /api/lead` | 5 req/min par IP+session | Sauvegarde lead + emails IONOS |
| `GET /api/history` | — | Historique de la session courante |
| `POST /api/history/clear` | — | Efface l'historique serveur |
| `GET /api/config` | — | Retourne la clé reCAPTCHA publique |
| `GET /health` | — | Santé du serveur |
| `POST /api/process` | 15 req/min par IP | Upload texte + images → parse IA → JSON structuré |
| `GET /api/process` | 15 req/min par IP | Liste les processus de la session |
| `GET /api/process/:id` | 15 req/min par IP | Détail complet d'un processus |
| `POST /api/process/:id/explain` | 15 req/min par IP | Explication IA d'une étape ou schéma |
| `DELETE /api/process/:id` | 15 req/min par IP | Supprime un processus (session propriétaire) |

### Module `processes.js`
- `parseWithAI(text, openai)` — parse via OpenAI avec `response_format: json_object`
- `parseWithRegex(text)` — fallback si OpenAI échoue (regex étapes/schémas/bullets)
- Images uploadées via multer dans `public/uploads/`, associées aux étapes par ordre d'index
- Stockage chiffré dans `db/processes.json` via `writeProcesses` / `readProcesses`
- Accès en lecture par UUID (pas de restriction session) — suppression réservée à la session propriétaire

## Variables d'environnement requises

Fichier `.env` en local (voir `.env.example`). Sur Render, configurées dans l'onglet Environment.

| Variable | Obligatoire | Note |
|---|---|---|
| `DATA_ENCRYPTION_KEY` | **Oui** — le serveur refuse de démarrer sans elle | Ne jamais changer après le premier démarrage |
| `OPENAI_API_KEY` | Oui | |
| `PPLX_API_KEY` | Oui | |
| `IONOS_EMAIL` / `IONOS_PASS` | Oui | SMTP fonctionne uniquement depuis les IPs Render, pas en local |
| `SMTP_HOST` / `SMTP_PORT` | Oui | `smtp.ionos.fr` / `465` |
| `FROM_EMAIL` / `ADMIN_EMAIL` | Oui | |
| `MAINTENANCE_MODE` | Non | `true` pour activer la page 503 |

## Points d'attention

- **`DATA_ENCRYPTION_KEY`** : si elle change en production, toutes les données `db/` deviennent illisibles. La conserver précieusement.
- **`cleanup.js`** : n'est pas importé dans `server.js` — doit être lancé manuellement (`node cleanup.js`) et doit être adapté pour utiliser `readJSON`/`atomicWriteJSON` car les fichiers `db/` sont chiffrés.
- **SMTP local** : IONOS bloque les connexions depuis les IP résidentielles. Les tests d'envoi d'email ne fonctionnent qu'en production (Render).
- **Moteur IA** : la sélection OpenAI vs Perplexity est faite côté client (`detectEngine()` dans `agent.js`) — le serveur ne valide pas ce choix.
