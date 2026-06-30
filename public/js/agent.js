(() => {
  const API_BASE = window.location.origin;

  const $ = (sel) => document.querySelector(sel);
  const log = (...args) => console.debug('[agent]', ...args);
  const agent = $('#agent-widget');
  const toggle = $('#agent-toggle');
  const panel = $('#agent-panel');
  const logBox = $('#agent-log');
  const chatForm = $('#agent-form');
  const input = $('#agent-input');
  log('boot', { agent: !!agent, toggle: !!toggle, panel: !!panel, logBox: !!logBox, chatForm: !!chatForm, input: !!input });

  // ══════════════════════════════════════════════
  // FONCTIONS UTILITAIRES (déclarées en premier)
  // ══════════════════════════════════════════════

  /**
   * Affiche un message dans le chat
   * @param {string} text - Contenu du message
   * @param {string} who - 'bot', 'user', ou 'you'
   * @param {string|null} engine - 'perplexity' ou 'openai' (pour badge)
   * @returns {HTMLElement} - L'élément DOM créé
   */
  function pushMsg(text, who = 'bot', engine = null) {
    if (!logBox) return null;

    const div = document.createElement('div');
    div.className = 'msg ' + who;
    // Badge moteur si applicable
    if (who === 'bot' && engine) {
      const badge = document.createElement('span');
      badge.className = 'engine-badge';
      badge.textContent = engine === 'perplexity' ? '🌐' : '🤖';
      badge.title = engine === 'perplexity' ? 'Réponse basée sur le web' : 'Réponse IA conversationnelle';
      div.appendChild(badge);
    }
    // Contenu avec support basique markdown — sans innerHTML pour éviter XSS
    const content = document.createElement('span');
    text.split('\n').forEach((line, i) => {
      if (i > 0) content.appendChild(document.createElement('br'));
      line.split(/\*\*(.*?)\*\*/g).forEach((part, j) => {
        if (j % 2 === 1) {
          const strong = document.createElement('strong');
          strong.textContent = part;
          content.appendChild(strong);
        } else {
          content.appendChild(document.createTextNode(part));
        }
      });
    });
    div.appendChild(content);
    logBox.appendChild(div);
    logBox.scrollTop = logBox.scrollHeight;

    return div;
  }

  /**
   * Affiche l'indicateur "en train d'écrire"
   */
  function showTyping() {
    if (document.getElementById('typing-indicator')) return; // Évite les doublons

    const msg = document.createElement('div');
    msg.id = 'typing-indicator';
    msg.className = 'msg bot typing';
    msg.innerHTML = '<span>⏳ L\'agent rédige une réponse…</span>';
    logBox.appendChild(msg);
    logBox.scrollTop = logBox.scrollHeight;
  }

  /**
   * Masque l'indicateur "en train d'écrire"
   */
  function hideTyping() {
    document.getElementById('typing-indicator')?.remove();
  }

  /**
   * Normalise un numéro de téléphone
   * @param {string} phone - Numéro brut
   * @returns {string} - Numéro normalisé au format international
   */
  function normalizePhone(phone) {
    if (!phone) return '';

    let cleaned = phone.trim().replace(/[\s.-]/g, '');
    // France : 06... → +336...
    if (cleaned.match(/^0\d{9}$/)) {
      cleaned = cleaned.replace(/^0(\d{9})$/, '+33$1');
    }
    // International : déjà au bon format
    else if (cleaned.match(/^\+\d{8,}$/)) {
      // OK
    }
    // Format non reconnu
    else {
      log('Téléphone non reconnu, conservé tel quel:', cleaned);
    }
    return cleaned;
  }

  /**
   * Extrait prénom et entreprise depuis un email
   * @param {string} email
   * @returns {Object} { prenom, entreprise, domaine }
   */
  function extraireInfosDepuisEmail(email) {
    const infos = { prenom: null, entreprise: null, domaine: null };
    if (!email || !email.includes('@')) return infos;
    const [localPart, domain] = email.split('@');
    infos.domaine = domain;
    const nomPossible = localPart.split(/[._-]/)[0];
    infos.prenom = nomPossible.charAt(0).toUpperCase() + nomPossible.slice(1).toLowerCase();
    const domainesPerso = ['gmail.com', 'yahoo.fr', 'hotmail.com', 'outlook.com', 'live.com', 'icloud.com'];
    const estPro = !domainesPerso.includes(domain.toLowerCase());
    if (estPro) {
      const nomSociete = domain.split('.')[0];
      infos.entreprise = nomSociete.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    }
    return infos;
  }

  /**
   * Message d'accueil avec carrousel
   */
  function pushWelcomeMsg() {
    if (!logBox) return;

    // 🔁 Supprime les anciens messages d’accueil avec carrousel s’ils existent
    const oldWelcome = logBox.querySelector('.capabilities-carousel');
    if (oldWelcome) {
      const parent = oldWelcome.closest('.msg.bot');
      if (parent) parent.remove();
    }

    const div = document.createElement('div');
    div.className = 'msg bot';

    const textSpan = document.createElement('span');
    textSpan.textContent = 'Bonjour ! Je suis l\'agent ProactifSystème. Posez votre question 🙂';
    div.appendChild(textSpan);

    const carousel = document.createElement('div');
    carousel.className = 'capabilities-carousel';
    carousel.innerHTML = `
    <div class="carousel-track">
      <div class="carousel-item">✨ Je me base sur des données sourcées pour vous répondre</div>
      <div class="carousel-item">🎯 J'apporte des solutions adaptées à vos besoins métier</div>
      <div class="carousel-item">📊 Je peux vous aider analyser les tendances du marché en temps réel</div>
      <div class="carousel-item">💡 Je qualifie vos demandes pour vous orienter efficacement</div>
      <div class="carousel-item">🌐 J'accède aux informations les plus récentes du web</div>
      <div class="carousel-item">🚀 Je propose des recommandations personnalisées</div>
      <div class="carousel-item">✨ Je me base sur des données sourcées pour vous répondre</div>
      <div class="carousel-item">🎯 J'apporte des solutions adaptées à vos besoins métier</div>
      <div class="carousel-item">📊 Je peux vous aider analyser les tendances du marché en temps réel</div>
      <div class="carousel-item">💡 Je qualifie vos demandes pour vous orienter efficacement</div>
      <div class="carousel-item">🌐 J'accède aux informations les plus récentes du web</div>
      <div class="carousel-item">🚀 Je propose des recommandations personnalisées</div>
    </div>
  `;
    div.appendChild(carousel);
    logBox.appendChild(div);
    logBox.scrollTop = logBox.scrollHeight;
  }

  // ══════════════════════════════════════════════
  // Détection automatique de moteur (IA choisit)
  // ══════════════════════════════════════════════

  function detectEngine(question) {
    const s = question.toLowerCase();
    // Commandes explicites (debug uniquement)
    if (s.startsWith('/perplexity')) return 'perplexity';
    if (s.startsWith('/openai')) return 'openai';
    // Mots-clés nécessitant données web récentes → Perplexity
    const perplexityKeywords = [
      'tendance', 'marché', 'actualité', 'prix', 'en 2025',
      'statistique', 'comparatif', 'derniers chiffres',
      'meilleur', 'évolution', 'étude', 'prévision',
      'données récentes', 'top', 'classement',
      'nouvelles', 'news', 'récent', 'actuellement',
      'dernier', 'mise à jour'
    ];
    // Questions business/qualification → OpenAI
    const openaiKeywords = [
      'mon secteur', 'mon entreprise', 'je cherche',
      'j\'ai besoin', 'nous voulons', 'comment automatiser',
      'quel outil', 'accompagnement', 'formation',
      'devis', 'tarif', 'prix de vos services',
      'vous proposez', 'vos offres', 'contact'
    ];
    if (openaiKeywords.some(k => s.includes(k))) return 'openai';
    if (perplexityKeywords.some(k => s.includes(k))) return 'perplexity';
    // Par défaut : OpenAI (qualification métier)
    return 'openai';
  }

  // ══════════════════════════════════════════════
  // API Fetch helper
  // ══════════════════════════════════════════════

  async function apiFetch(path, options = {}) {
    const res = await fetch(`${API_BASE}${path}`, {
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
      ...options
    });
    let body = null;
    try { body = await res.json(); } catch { }
    return { ok: res.ok, status: res.status, body };
  }

  // ══════════════════════════════════════════════
  // Reconnaissance vocale
  // ══════════════════════════════════════════════

  function startVoiceRecognition() {
    if (!('webkitSpeechRecognition' in window)) return;
    const rec = new webkitSpeechRecognition();
    rec.lang = 'fr-FR';
    rec.interimResults = false;
    rec.maxAlternatives = 1;
    rec.onresult = (e) => {
      const text = e.results[0][0].transcript;
      input.value = text;
      chatForm?.requestSubmit();
    };
    rec.onerror = (err) => log('Speech recognition error:', err);
    rec.start();
  }

  // ══════════════════════════════════════════════
  // Chargement de l'historique
  // ══════════════════════════════════════════════

  async function loadHistory() {
    // Ne pas charger l'historique si effacé dans cette session
    const skipKey = 'agent.historyCleared';
    if (sessionStorage.getItem(skipKey) === '1') {
      sessionStorage.removeItem(skipKey); // Reset pour prochaine visite
      return;
    }
    try {
      const { ok, body } = await apiFetch('/api/history');
      if (!ok || !body?.messages) return;
      logBox.innerHTML = '';
      for (const m of body.messages) {
        pushMsg(m.content, m.role === 'user' ? 'you' : 'bot');
      }
      const toolbar = document.getElementById('agent-toolbar');
      if (toolbar) {
        toolbar.style.display = logBox.children.length > 0 ? 'flex' : 'none';
      }
    } catch (e) {
      log('history error', e);
    }
  }

  // ══════════════════════════════════════════════
  // Toggle widget
  // ══════════════════════════════════════════════

  toggle?.addEventListener('click', () => {
    const isOpen = agent.classList.toggle('open');
    log('toggle →', isOpen);
    if (isOpen) {
      input?.focus();
      startVoiceRecognition();
    }
  });

  $('#open-agent')?.addEventListener('click', (e) => {
    e.preventDefault();
    agent.classList.add('open');
    input?.focus();
    startVoiceRecognition();
  });

  // ══════════════════════════════════════════════
  // Actions toolbar (fermer, agrandir, minimiser, effacer)
  // ══════════════════════════════════════════════

  let clearTimeoutId = null;
  document.addEventListener('click', async (e) => {
    const t = e.target;
    if (!t || !(t instanceof HTMLElement)) return;
    if (t.id === 'agent-close') {
      e.preventDefault();
      agent.classList.remove('open', 'max', 'min');

      // Annule le timeout si le chat est fermé avant la fin
      if (clearTimeoutId) {
        clearTimeout(clearTimeoutId);
        clearTimeoutId = null;
      }
    }
    if (t.id === 'agent-expand') {
      e.preventDefault();
      agent.classList.toggle('max');
      agent.classList.remove('min');
    }
    if (t.id === 'agent-minimize') {
      e.preventDefault();
      agent.classList.toggle('min');
      agent.classList.remove('max');
    }
    if (t.id === 'agent-clear') {
      e.preventDefault();
      logBox.innerHTML = '';
      const msg = pushMsg('Historique effacé. 🙈', 'bot');
      sessionStorage.setItem('agent.historyCleared', '1');
      try {
        await apiFetch('/api/history/clear', { method: 'POST' });
      } catch (err) {
        log('Erreur lors de l\'effacement serveur', err);
      }
      // Efface le message temporaire après 3 secondes
      clearTimeoutId = setTimeout(() => {
        msg?.remove();
        pushWelcomeMsg();
        clearTimeoutId = null;
      }, 3000);
    }
  }, true);

  // ══════════════════════════════════════════════
  // Raccourcis clavier
  // ══════════════════════════════════════════════

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && agent?.classList.contains('open')) {
      agent.classList.remove('open');
      panel?.classList.remove('max', 'min');
    }
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && document.activeElement === input) {
      chatForm?.requestSubmit();
    }
  });

  // ══════════════════════════════════════════════
  // Soumission de message (choix automatique moteur)
  // ══════════════════════════════════════════════

  chatForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    let q = input.value.trim();
    if (!q) return;
    // Détection automatique du moteur
    const engine = detectEngine(q);
    const endpoint = engine === 'perplexity' ? '/api/perplexity' : '/api/agent';
    // Nettoyage commandes debug si présentes
    if (q.startsWith('/perplexity ') || q.startsWith('/openai ')) {
      q = q.replace(/^\/(perplexity|openai)\s+/, '');
    }
    // Supprime le message d'accueil avec carousel dès le premier message
    const welcomeCarousel = logBox.querySelector('.capabilities-carousel');
    if (welcomeCarousel) {
      const welcomeMsg = welcomeCarousel.closest('.msg.bot');
      if (welcomeMsg) welcomeMsg.remove();
    }
    pushMsg(q, 'you');
    input.value = '';
    showTyping();
    try {
      const { ok, status, body } = await apiFetch(endpoint, {
        method: 'POST',
        body: JSON.stringify({ q })
      });
      hideTyping();
      const msg = body?.a || (
        status === 429 ? '🚦 Trop de requêtes. Attendez 1 minute.' :
          status === 504 ? '⏱️ Temps dépassé. Réessayez avec une question plus courte.' :
            'Service indisponible.'
      );
      pushMsg(msg, 'bot', engine);
    } catch (err) {
      hideTyping();
      pushMsg('Erreur réseau. Vérifiez votre connexion.', 'bot');
      log('Erreur réseau:', err);
    }
  });

  // ══════════════════════════════════════════════
  // Auto-remplissage formulaire lead depuis email
  // ══════════════════════════════════════════════

  let entrepriseInput = document.querySelector('input[name="entreprise"]');
  document.querySelector('input[name="email"]')?.addEventListener('input', (e) => {
    const email = e.target.value.trim();
    if (!email.includes('@')) return;
    const infos = extraireInfosDepuisEmail(email);
    // Mise à jour prénom si vide
    const nameInput = document.querySelector('input[name="name"]');
    if (infos.prenom && nameInput && !nameInput.value) {
      nameInput.value = infos.prenom;
    }
    // Mise à jour ou création champ entreprise
    if (infos.entreprise) {
      if (!entrepriseInput) {
        entrepriseInput = document.createElement('input');
        entrepriseInput.type = 'text';
        entrepriseInput.name = 'entreprise';
        entrepriseInput.placeholder = 'Nom de l\'entreprise';
        entrepriseInput.required = false;
        entrepriseInput.style.marginBottom = '1em';
        const form = document.getElementById('lead-form');
        const textarea = form?.querySelector('textarea');
        if (form && textarea) {
          form.insertBefore(entrepriseInput, textarea);
        }
      }
      entrepriseInput.value = infos.entreprise;
    }
  });

  // ══════════════════════════════════════════════
  // Gestion de l'envoi du formulaire lead
  // ══════════════════════════════════════════════

  const leadForm = document.getElementById('lead-form');
  const leadStatus = document.getElementById('lead-status');
  // ══════════════════════════════════════════════
  // Validation des champs avant envoi du formulaire
  // ══════════════════════════════════════════════
  // ✅ Fonction pour mettre en évidence un champ en erreur
  function highlightErrorField(field) {
    if (!field) return;
    field.style.border = '2px solid #ff4444';
    field.style.transition = 'border 0.3s ease';
    setTimeout(() => (field.style.border = ''), 1500);
  }

  function isValidEmail(email) {
    const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return regex.test(email);
  }

  function isValidPhone(phone) {
    // Accepte formats FR et internationaux (+33, 0X, etc.)
    const regex = /^(\+?\d{1,3}[- ]?)?\d{6,14}$/;
    return regex.test(phone.replace(/\s+/g, ''));
  }

  if (leadForm) {
    leadForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (leadStatus) {
        leadStatus.textContent = '⏳ Envoi en cours...';
        leadStatus.style.color = '#ffaa00';
      }
      const data = Object.fromEntries(new FormData(leadForm).entries());
      // Validation basique avant envoi
      if (!isValidEmail(data.email)) {
        leadStatus.textContent = '❌ Adresse e-mail invalide.';
        leadStatus.style.color = '#ff4444';
        highlightErrorField(leadForm.querySelector('input[name="email"]'));
        return;
      }

      if (data.phone && !isValidPhone(data.phone)) {
        leadStatus.textContent = '❌ Numéro de téléphone invalide.';
        leadStatus.style.color = '#ff4444';
        highlightErrorField(leadForm.querySelector('input[name="phone"]'));
        return;
      }


      // Normalisation du téléphone
      if (data.phone) {
        data.phone = normalizePhone(data.phone);
      }
      try {
        const res = await fetch(`${API_BASE}/api/lead`, {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data)
        });
        const result = await res.json();
        if (result.ok) {
          if (leadStatus) {
            leadStatus.textContent = result.message || '✅ Message envoyé avec succès !';
            leadStatus.style.color = '#00cc66';
          }
          alert('✅ Votre message a bien été envoyé.\nVous recevrez une confirmation par e-mail sous 24h.');
          leadForm.reset();
        } else {
          if (leadStatus) {
            leadStatus.textContent = result.message || '❌ Une erreur est survenue.';
            leadStatus.style.color = '#ff4444';
          }
          alert('⚠️ Erreur : ' + (result.message || 'Impossible d\'envoyer votre message.'));
        }
      } catch (err) {
        if (leadStatus) {
          leadStatus.textContent = '❌ Erreur réseau. Vérifiez votre connexion.';
          leadStatus.style.color = '#ff4444';
        }
        alert('❌ Impossible de contacter le serveur.\nVérifiez votre connexion ou réessayez plus tard.');
        log('Erreur envoi lead:', err);
      }
    });
  }

  // ══════════════════════════════════════════════
  // Bouton FAQ du menu principal → ouvre chatbot + FAQ
  // ══════════════════════════════════════════════

  document.getElementById('faq-menu-btn')?.addEventListener('click', () => {
    const isOpen = agent.classList.contains('open');
    // Si le chatbot n'est pas encore ouvert → on l'ouvre
    if (!isOpen) {
      agent.classList.add('open');
      input?.focus();
    }
    // Dans tous les cas, déclenche la FAQ après un petit délai
    setTimeout(() => {
      const faqBtn = document.getElementById('faq-open');
      if (faqBtn) {
        faqBtn.click();
      } else {
        log('Bouton #faq-open non trouvé');
      }
    }, 400);
  });

  // ══════════════════════════════════════════════
  // FAQ INTERACTIVE : Navigation et injection dans input
  // ══════════════════════════════════════════════

  (() => {
    const faqData = [
      {
        question: "Comment l'IA peut-elle m'aider dans mon entreprise ?",
        answer: "Elle automatise vos tâches répétitives, qualifie vos leads et répond à vos clients 24h/24."
      },
      {
        question: "L'IA peut-elle générer un devis ou une liste de matériel ?",
        answer: "Oui, à partir de vos plans ou de vos besoins, elle peut générer un métré ou des estimations automatiquement."
      },
      {
        question: "Est-ce que mes données sont confidentielles ?",
        answer: "Oui, toutes les données sont stockées de façon sécurisée et ne sont jamais partagées."
      },
      {
        question: "Quels outils l'IA peut-elle remplacer ou accélérer ?",
        answer: "Elle peut s'intégrer avec vos CRM, logiciels de devis, outils d'analyse ou votre site web."
      }
    ];
    let currentFaqIndex = 0;
    const faqBox = document.getElementById('faq-box');
    const faqContent = document.getElementById('faq-content');
    const faqOpen = document.getElementById('faq-open');
    const faqPrev = document.getElementById('faq-prev');
    const faqNext = document.getElementById('faq-next');
    const faqClose = document.getElementById('faq-close');

    function renderFaq(index) {
      const item = faqData[index];
      if (!item || !faqContent) return;
      faqContent.innerHTML = `
        <strong class="faq-question-click" style="color:#4ade80; cursor:pointer;">❓ ${item.question}</strong>
        <p style="margin-top: 6px;">${item.answer}</p>
      `;
      // Attache le clic à la question pour l'envoyer dans le champ
      faqContent.querySelector('.faq-question-click')?.addEventListener('click', () => {
        if (input) {
          input.value = item.question;
          input.focus();
          if (faqBox) faqBox.style.display = 'none';
        }
      });
    }

    function showFaq() {
      if (!faqBox) return;
      currentFaqIndex = 0;
      renderFaq(currentFaqIndex);
      faqBox.style.display = 'block';
      faqBox.scrollIntoView({ behavior: 'smooth' });
    }

    function hideFaq() {
      if (faqBox) faqBox.style.display = 'none';
    }

    faqOpen?.addEventListener('click', showFaq);
    faqNext?.addEventListener('click', () => {
      currentFaqIndex = (currentFaqIndex + 1) % faqData.length;
      renderFaq(currentFaqIndex);
    });
    faqPrev?.addEventListener('click', () => {
      currentFaqIndex = (currentFaqIndex - 1 + faqData.length) % faqData.length;
      renderFaq(currentFaqIndex);
    });
    faqClose?.addEventListener('click', hideFaq);
  })();

  // ══════════════════════════════════════════════
  // Initialisation
  // ══════════════════════════════════════════════

  const ensureClickable = () => {
    [toggle, panel, document.querySelector('.agent-header'), ...document.querySelectorAll('.icon-btn')]
      .filter(Boolean)
      .forEach(el => el.style.pointerEvents = 'auto');
  };
  ensureClickable();

  if (logBox) {
    loadHistory().then(() => {
      if (!logBox.children.length) {
        pushWelcomeMsg();
      }
    });
  }

  log('Agent prêt ✅');
})();
