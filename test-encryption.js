// test-encryption.js
const { encrypt, decrypt } = require('./encryption');

const testData = {
    name: 'ProactifSystème',
    message: 'Test de chiffrement AES-256-CBC avec clé dynamique.',
    timestamp: new Date().toISOString()
};

console.log('🔹 Données originales :');
console.log(testData);

const json = JSON.stringify(testData, null, 2);

// --- Étape 1 : Chiffrement ---
const encrypted = encrypt(json);
console.log('\n🔒 Données chiffrées :');
console.log(encrypted);

// --- Étape 2 : Déchiffrement ---
const decrypted = decrypt(encrypted);
console.log('\n🔓 Données déchiffrées :');
console.log(JSON.parse(decrypted));

// --- Vérification automatique ---
if (decrypted === json) {
    console.log('\n✅ Test réussi : le chiffrement/déchiffrement fonctionne parfaitement.');
} else {
    console.error('\n❌ Erreur : les données ne correspondent pas après déchiffrement.');
}
