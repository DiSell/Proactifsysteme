// perplexity.js
'use strict';
require('dotenv').config();
const axios = require('axios');

async function askPerplexity(question) {
    if (!process.env.PPLX_API_KEY) {
        throw new Error('PPLX_API_KEY manquant dans .env');
    }

    try {
        const response = await axios.post(
            'https://api.perplexity.ai/chat/completions',
            {
                model: 'sonar-pro', // fiable et rapide
                messages: [
                    {
                        role: 'system',
                        content:
                            "Tu es l'assistant IA de ProactifSystème. Réponds de manière claire, concise et utile pour les PME et indépendants.",
                    },
                    { role: 'user', content: question },
                ],
                temperature: 0.7,
                max_tokens: 500,
            },
            {
                headers: {
                    Authorization: `Bearer ${process.env.PPLX_API_KEY}`,
                    'Content-Type': 'application/json',
                },
                timeout: 15_000,
            }
        );

        const text =
            response.data?.choices?.[0]?.message?.content ||
            '🤖 Aucune réponse reçue.';
        return text.trim();
    } catch (err) {
        const msg =
            err.response?.data?.error?.message ||
            err.response?.data?.message ||
            err.message;
        console.error('[Perplexity] Erreur API →', msg);
        throw new Error('Erreur API Perplexity');
    }
}

module.exports = { askPerplexity };
