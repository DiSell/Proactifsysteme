const nodemailer = require('nodemailer');

// ════════════════════════════════════════════════════════
// CONFIGURATION SMTP
// ════════════════════════════════════════════════════════
const transporter = nodemailer.createTransport({
    service: 'gmail', // tu peux remplacer par "ionos", "hotmail", etc.
    auth: {
        user: process.env.ALERT_EMAIL_USER,
        pass: process.env.ALERT_EMAIL_PASS
    }
});

// ════════════════════════════════════════════════════════
// 📧 Envoi d’un email d’alerte administrateur
// ════════════════════════════════════════════════════════
function sendAlertEmail(subject, text) {
    const mailOptions = {
        from: process.env.ALERT_EMAIL_USER,
        to: process.env.ADMIN_EMAIL,
        subject,
        text
    };

    return transporter.sendMail(mailOptions)
        .then(info => {
            console.log('📨 Alerte email envoyée :', info.response);
        })
        .catch(err => {
            console.error('❌ Erreur envoi alerte email :', err.message);
        });
}

// ════════════════════════════════════════════════════════
// 🚨 Page de maintenance (utilisateur)
// ════════════════════════════════════════════════════════
function showMaintenanceAlert(req, res) {
    res.status(503).send(`
    <html lang="fr">
      <head>
        <meta charset="UTF-8">
        <title>Maintenance — ProactifSystème</title>
        <style>
          body {
            background: #0b1220;
            color: #eaf0ff;
            font-family: 'Segoe UI', sans-serif;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            height: 100vh;
            text-align: center;
          }
          h1 {
            font-size: 2.2rem;
            margin-bottom: 10px;
            color: #60a5fa;
          }
          p {
            color: #a9b3ca;
            font-size: 1.1rem;
            max-width: 500px;
          }
        </style>
      </head>
      <body>
        <h1>🚧 ProactifSystème est en maintenance</h1>
        <p>Nos services sont temporairement indisponibles pour une mise à jour.</p>
        <p>Veuillez réessayer dans quelques minutes. Merci de votre patience 🙏</p>
      </body>
    </html>
  `);
}

// ════════════════════════════════════════════════════════
// EXPORT
// ════════════════════════════════════════════════════════
module.exports = { sendAlertEmail, showMaintenanceAlert };
