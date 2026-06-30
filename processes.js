'use strict';
const fs = require('fs').promises;
const path = require('path');
const { encrypt, decrypt } = require('./encryption');

const PROCESSES_PATH = path.join(__dirname, 'db', 'processes.json');
const UPLOADS_DIR = path.join(__dirname, 'public', 'uploads');

async function ensureUploadsDir() {
  await fs.mkdir(UPLOADS_DIR, { recursive: true });
}

async function readProcesses() {
  try {
    const data = await fs.readFile(PROCESSES_PATH, 'utf8');
    const decrypted = decrypt(data);
    return JSON.parse(decrypted || data || '{}');
  } catch {
    return {};
  }
}

async function writeProcesses(obj) {
  const tmp = `${PROCESSES_PATH}.tmp`;
  await fs.writeFile(tmp, encrypt(JSON.stringify(obj, null, 2)), 'utf8');
  await fs.rename(tmp, PROCESSES_PATH);
}

async function parseWithAI(text, openai) {
  const result = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [{
      role: 'user',
      content: `Tu es un expert en automatisation de processus métier pour ProactifSystème (solutions IA sur mesure).

Analyse ce texte de processus. Retourne UNIQUEMENT un JSON valide.

TEXTE:
${text.slice(0, 4000)}

Structure JSON attendue:
{
  "title": "titre général du processus",
  "steps": [
    { "index": 1, "title": "titre court de l'étape", "description": "description complète" }
  ],
  "schemas": [
    { "index": 1, "title": "titre du schéma", "description": "description du schéma" }
  ]
}

Règles:
- Extrais toutes les étapes (numérotées, tirets, Étape X, Step X, etc.)
- Extrais les schémas/diagrammes/flux mentionnés explicitement
- Si aucun schéma mentionné: schemas = []
- title = titre global du processus (déduit du contenu si absent)`
    }],
    max_tokens: 1500,
    temperature: 0.1,
    response_format: { type: 'json_object' }
  });

  const parsed = JSON.parse(result.choices[0].message.content);
  if (!Array.isArray(parsed.steps)) parsed.steps = [];
  if (!Array.isArray(parsed.schemas)) parsed.schemas = [];
  return parsed;
}

function parseWithRegex(text) {
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
  const title = lines[0] || 'Processus';
  const steps = [];
  const schemas = [];

  const stepRx = /^(?:étape\s*)?(\d+)[.:)]\s*(.+)/i;
  const schemaRx = /^(?:schéma|schema|diagramme|flux|flow)\s*(\d*)[.:)]\s*(.+)/i;
  const bulletRx = /^[-*•]\s+(.+)/;

  let bulletIndex = 1;
  for (let i = 1; i < lines.length; i++) {
    const schemaM = lines[i].match(schemaRx);
    if (schemaM) {
      schemas.push({ index: schemas.length + 1, title: schemaM[2].slice(0, 100), description: schemaM[2] });
      continue;
    }
    const stepM = lines[i].match(stepRx);
    if (stepM) {
      steps.push({ index: parseInt(stepM[1]), title: stepM[2].slice(0, 100), description: stepM[2] });
      continue;
    }
    const bulletM = lines[i].match(bulletRx);
    if (bulletM) {
      steps.push({ index: bulletIndex++, title: bulletM[1].slice(0, 100), description: bulletM[1] });
      continue;
    }
    if (steps.length > 0 && lines[i].length > 3) {
      steps[steps.length - 1].description += ' ' + lines[i];
    }
  }

  return { title, steps, schemas };
}

module.exports = { readProcesses, writeProcesses, parseWithAI, parseWithRegex, PROCESSES_PATH, UPLOADS_DIR, ensureUploadsDir };
