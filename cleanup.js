// cleanup.js
const fs = require('fs').promises;
const path = require('path');

const LEADS_PATH = path.join(__dirname, 'db', 'leads.json');

(async () => {
    try {
        const data = await fs.readFile(LEADS_PATH, 'utf8');
        const leads = JSON.parse(data);

        const now = Date.now();
        const oneYear = 365 * 24 * 60 * 60 * 1000; // une année en millisecondes

        const filteredLeads = leads.filter(lead => {
            const leadTimestamp = new Date(lead.timestamp).getTime();
            return (now - leadTimestamp) <= oneYear; // on garde les entrées de moins d'un an
        });

        if (filteredLeads.length !== leads.length) {
            await fs.writeFile(LEADS_PATH, JSON.stringify(filteredLeads, null, 2), 'utf8');
            console.log('✨ Données nettoyées : les entrées de plus d’un an ont été supprimées.');
        } else {
            console.log('✅ Aucune donnée à supprimer.');
        }
    } catch (err) {
        console.error('❌ Erreur lors du nettoyage des données :', err.message);
    }
})();
