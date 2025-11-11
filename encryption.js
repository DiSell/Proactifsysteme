// encryption.js
const crypto = require('crypto');

const ALGO = 'aes-256-cbc';
const SECRET_KEY = crypto
    .createHash('sha256')
    .update(String(process.env.DATA_ENCRYPTION_KEY || 'ProactifSysteme_Default_Key'))
    .digest('base64')
    .substr(0, 32);
const IV_LENGTH = 16;

function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGO, Buffer.from(SECRET_KEY), iv);
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(data) {
    try {
        const [ivHex, encryptedHex] = data.split(':');
        const iv = Buffer.from(ivHex, 'hex');
        const encryptedText = Buffer.from(encryptedHex, 'hex');
        const decipher = crypto.createDecipheriv(ALGO, Buffer.from(SECRET_KEY), iv);
        const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
        return decrypted.toString('utf8');
    } catch (e) {
        return null;
    }
}

module.exports = { encrypt, decrypt };
