/* ═══════════════════════════════════════════════════════════
   ProactifSystème — Widget IA embarquable
   Usage : <script src="https://proactifsystem-server.onrender.com/embed.js"
              id="psa-embed"
              data-name="Mon Assistant"
              data-color="#3b82f6"
              data-welcome="Bonjour ! Comment puis-je vous aider ?"
              defer></script>
═══════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  /* ── Configuration via attributs data-* ──────────────────── */
  const script =
    document.getElementById('psa-embed') ||
    [...document.querySelectorAll('script')].find(s => s.src && s.src.includes('embed.js'));

  const API_BASE     = (script && script.dataset.api)         || 'https://proactifsystem-server.onrender.com';
  const COLOR        = (script && script.dataset.color)       || '#3b82f6';
  const AGENT_NAME   = (script && script.dataset.name)        || 'Agent IA ProactifSystème';
  const WELCOME_MSG  = (script && script.dataset.welcome)     || 'Bonjour ! Je suis votre assistant IA. Comment puis-je vous aider ?';
  const PLACEHOLDER  = (script && script.dataset.placeholder) || 'Posez votre question…';
  const BUBBLE_DELAY = parseInt(script && script.dataset.delay || '4000', 10);

  /* ── Session locale (localStorage, sans cookie cross-origin) */
  const SESSION_KEY = '_psa_sid';
  function getSessionId() {
    let sid;
    try { sid = localStorage.getItem(SESSION_KEY); } catch {}
    if (!sid) {
      sid = 'e_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 9);
      try { localStorage.setItem(SESSION_KEY, sid); } catch {}
    }
    return sid;
  }
  const SESSION_ID = getSessionId();

  /* ── CSS injecté ─────────────────────────────────────────── */
  const PRIMARY    = COLOR;
  const DARK       = '#0e1826';
  const DARK2      = '#162033';
  const BORDER     = 'rgba(255,255,255,0.08)';
  const TEXT       = '#eef2ff';
  const MUTED      = '#8892a4';

  const css = `
    #psa-widget *,#psa-widget *::before,#psa-widget *::after{box-sizing:border-box;margin:0;padding:0;}
    #psa-widget{position:fixed;bottom:20px;right:20px;z-index:2147483647;font-family:'Segoe UI',system-ui,-apple-system,sans-serif;font-size:15px;}

    /* Bulle d'accueil */
    #psa-bubble{
      display:none;
      position:absolute;
      bottom:76px;right:0;
      background:${PRIMARY};
      color:#fff;
      padding:10px 16px;
      border-radius:12px 12px 4px 12px;
      white-space:nowrap;
      font-size:13px;font-weight:600;
      box-shadow:0 4px 16px rgba(0,0,0,0.3);
      animation:psa-pop .3s ease;
      cursor:pointer;
    }
    #psa-bubble::after{
      content:'';position:absolute;bottom:-6px;right:16px;
      border:6px solid transparent;border-top-color:${PRIMARY};border-bottom:none;
    }

    /* Bouton flottant */
    #psa-toggle{
      width:60px;height:60px;border-radius:50%;border:none;cursor:pointer;
      background:${PRIMARY};color:#fff;font-size:26px;
      box-shadow:0 6px 24px rgba(59,130,246,.5);
      transition:transform .2s,box-shadow .2s;
      display:flex;align-items:center;justify-content:center;
    }
    #psa-toggle:hover{transform:scale(1.08);box-shadow:0 8px 30px rgba(59,130,246,.65);}

    /* Panel */
    #psa-panel{
      display:none;flex-direction:column;
      position:absolute;bottom:76px;right:0;
      width:340px;height:480px;
      background:${DARK};
      border:1px solid ${BORDER};
      border-radius:16px;
      box-shadow:0 16px 48px rgba(0,0,0,.6);
      overflow:hidden;
    }

    /* Header */
    #psa-header{
      background:${DARK2};
      border-bottom:1px solid ${BORDER};
      padding:14px 16px;
      display:flex;align-items:center;justify-content:space-between;
      flex-shrink:0;
    }
    #psa-header-info{display:flex;align-items:center;gap:10px;}
    #psa-avatar{
      width:34px;height:34px;border-radius:50%;
      background:${PRIMARY};
      display:flex;align-items:center;justify-content:center;
      font-size:17px;flex-shrink:0;
    }
    #psa-header-text strong{display:block;font-size:13px;font-weight:700;color:${TEXT};}
    #psa-status{font-size:11px;color:#4ade80;display:flex;align-items:center;gap:4px;}
    #psa-status::before{content:'';width:6px;height:6px;border-radius:50%;background:#4ade80;display:inline-block;}
    #psa-close-btn{
      background:none;border:none;color:${MUTED};font-size:18px;cursor:pointer;
      line-height:1;padding:2px 4px;border-radius:4px;transition:color .2s;
    }
    #psa-close-btn:hover{color:${TEXT};}

    /* Log messages */
    #psa-log{
      flex:1;overflow-y:auto;padding:14px 12px;display:flex;flex-direction:column;gap:8px;
      scrollbar-width:thin;scrollbar-color:rgba(255,255,255,.1) transparent;
    }
    #psa-log::-webkit-scrollbar{width:4px;}
    #psa-log::-webkit-scrollbar-track{background:transparent;}
    #psa-log::-webkit-scrollbar-thumb{background:rgba(255,255,255,.12);border-radius:4px;}

    .psa-msg{display:flex;max-width:85%;}
    .psa-msg.psa-bot{align-self:flex-start;}
    .psa-msg.psa-user{align-self:flex-end;flex-direction:row-reverse;}
    .psa-msg span{
      display:inline-block;padding:9px 13px;border-radius:12px;
      font-size:13px;line-height:1.5;word-break:break-word;
    }
    .psa-msg.psa-bot span{background:${DARK2};color:${TEXT};border:1px solid ${BORDER};border-radius:4px 12px 12px 12px;}
    .psa-msg.psa-user span{background:${PRIMARY};color:#fff;border-radius:12px 4px 12px 12px;}
    .psa-msg.psa-typing span{color:${MUTED};font-style:italic;letter-spacing:.5px;}

    /* Formulaire */
    #psa-form{
      display:flex;gap:8px;padding:10px 12px;
      border-top:1px solid ${BORDER};
      background:${DARK};flex-shrink:0;
    }
    #psa-input{
      flex:1;background:rgba(0,0,0,.3);color:${TEXT};
      border:1px solid ${BORDER};border-radius:8px;
      padding:9px 12px;font-size:13px;font-family:inherit;outline:none;
      transition:border-color .2s;
    }
    #psa-input:focus{border-color:${PRIMARY};}
    #psa-input::placeholder{color:${MUTED};opacity:.8;}
    #psa-send{
      background:${PRIMARY};color:#fff;border:none;border-radius:8px;
      padding:9px 14px;font-size:13px;font-weight:700;font-family:inherit;
      cursor:pointer;transition:background .2s;flex-shrink:0;
    }
    #psa-send:hover{background:#2563eb;}
    #psa-send:disabled{opacity:.5;cursor:not-allowed;}

    /* Branding bas */
    #psa-brand{
      text-align:center;font-size:10px;color:${MUTED};
      padding:5px;background:${DARK2};border-top:1px solid ${BORDER};
      flex-shrink:0;
    }
    #psa-brand a{color:${MUTED};text-decoration:none;}
    #psa-brand a:hover{color:${TEXT};}

    /* Animations */
    @keyframes psa-pop{from{opacity:0;transform:scale(.85) translateY(4px);}to{opacity:1;transform:scale(1) translateY(0);}}
    @keyframes psa-slide{from{opacity:0;transform:translateY(12px);}to{opacity:1;transform:translateY(0);}}
    #psa-panel[style*="flex"]{animation:psa-slide .22s ease;}

    /* Mobile */
    @media(max-width:480px){
      #psa-widget{bottom:12px;right:12px;}
      #psa-panel{
        position:fixed;bottom:0;right:0;left:0;
        width:100%;height:70vh;border-radius:16px 16px 0 0;
      }
      #psa-toggle{width:54px;height:54px;font-size:24px;}
    }
  `;

  const styleEl = document.createElement('style');
  styleEl.textContent = css;
  document.head.appendChild(styleEl);

  /* ── HTML injecté ────────────────────────────────────────── */
  const widget = document.createElement('div');
  widget.id = 'psa-widget';
  widget.innerHTML = `
    <div id="psa-bubble">${WELCOME_MSG.split('!')[0] + ' !'}</div>
    <button id="psa-toggle" aria-label="Ouvrir le chat">💬</button>
    <div id="psa-panel" role="dialog" aria-label="Chat assistant">
      <div id="psa-header">
        <div id="psa-header-info">
          <div id="psa-avatar">🤖</div>
          <div id="psa-header-text">
            <strong>${AGENT_NAME}</strong>
            <span id="psa-status">En ligne</span>
          </div>
        </div>
        <button id="psa-close-btn" aria-label="Fermer">✕</button>
      </div>
      <div id="psa-log" role="log" aria-live="polite"></div>
      <form id="psa-form" autocomplete="off">
        <input id="psa-input" type="text" placeholder="${PLACEHOLDER}" aria-label="Votre message" />
        <button id="psa-send" type="submit" aria-label="Envoyer">Envoyer</button>
      </form>
      <div id="psa-brand">Propulsé par <a href="https://proactifsystem-server.onrender.com" target="_blank" rel="noopener">ProactifSystème</a></div>
    </div>
  `;
  document.body.appendChild(widget);

  /* ── Références DOM ──────────────────────────────────────── */
  const toggleBtn  = document.getElementById('psa-toggle');
  const panel      = document.getElementById('psa-panel');
  const closeBtn   = document.getElementById('psa-close-btn');
  const bubble     = document.getElementById('psa-bubble');
  const log        = document.getElementById('psa-log');
  const form       = document.getElementById('psa-form');
  const inputEl    = document.getElementById('psa-input');
  const sendBtn    = document.getElementById('psa-send');

  let isOpen = false;
  let msgCount = 0;

  /* ── Ouvrir / fermer ─────────────────────────────────────── */
  function openChat() {
    isOpen = true;
    panel.style.display = 'flex';
    bubble.style.display = 'none';
    inputEl.focus();
    if (msgCount === 0) addMsg(WELCOME_MSG, 'bot');
  }

  function closeChat() {
    isOpen = false;
    panel.style.display = 'none';
  }

  toggleBtn.addEventListener('click', () => isOpen ? closeChat() : openChat());
  closeBtn.addEventListener('click', closeChat);
  bubble.addEventListener('click', openChat);

  /* ── Ajouter un message ──────────────────────────────────── */
  function addMsg(text, who) {
    const div = document.createElement('div');
    div.className = 'psa-msg psa-' + who;
    const span = document.createElement('span');
    // Rendu basique du markdown **gras**
    text.split('\n').forEach((line, i) => {
      if (i > 0) span.appendChild(document.createElement('br'));
      line.split(/\*\*(.*?)\*\*/g).forEach((part, j) => {
        if (j % 2 === 1) {
          const b = document.createElement('strong');
          b.textContent = part;
          span.appendChild(b);
        } else {
          span.appendChild(document.createTextNode(part));
        }
      });
    });
    div.appendChild(span);
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
    msgCount++;
    return div;
  }

  /* ── Indicateur de frappe ────────────────────────────────── */
  function showTyping() {
    const div = document.createElement('div');
    div.className = 'psa-msg psa-bot psa-typing';
    div.id = 'psa-typing';
    const span = document.createElement('span');
    span.textContent = '⏳ Rédaction…';
    div.appendChild(span);
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
  }
  function hideTyping() {
    document.getElementById('psa-typing')?.remove();
  }

  /* ── Appel API ───────────────────────────────────────────── */
  async function sendMessage(text) {
    addMsg(text, 'user');
    inputEl.value = '';
    sendBtn.disabled = true;
    showTyping();

    try {
      const res = await fetch(`${API_BASE}/api/agent`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Session-Id': SESSION_ID
        },
        body: JSON.stringify({ q: text })
      });
      const data = await res.json();
      hideTyping();
      addMsg(data.a || 'Désolé, une erreur est survenue.', 'bot');
    } catch {
      hideTyping();
      addMsg('Erreur de connexion. Vérifiez votre réseau.', 'bot');
    } finally {
      sendBtn.disabled = false;
      inputEl.focus();
    }
  }

  /* ── Soumission formulaire ───────────────────────────────── */
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const text = inputEl.value.trim();
    if (!text || sendBtn.disabled) return;
    sendMessage(text);
  });

  /* ── Touche Entrée ───────────────────────────────────────── */
  inputEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      form.dispatchEvent(new Event('submit'));
    }
  });

  /* ── Fermer avec Escape ──────────────────────────────────── */
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && isOpen) closeChat();
  });

  /* ── Bulle d'accueil différée ────────────────────────────── */
  if (BUBBLE_DELAY >= 0) {
    setTimeout(() => {
      if (!isOpen) bubble.style.display = 'block';
    }, BUBBLE_DELAY);
  }

})();
