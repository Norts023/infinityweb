/**
 * @file chat.js
 * @description Widget de atendimento por IA — Infinity AI Chat.
 *              Gerencia abertura/fechamento, envio de mensagens,
 *              chamadas ao proxy Groq e renderização das respostas.
 *
 * Dependências:
 *  - DOMPurify 3.x   (carregado antes deste script via CDN)
 *  - assets/css/chat.css (estilos do widget)
 *
 * Segurança implementada (detalhes nos comentários inline):
 *  - CWE-79  (XSS): saída de bot sanitizada com DOMPurify antes de innerHTML.
 *  - CWE-20  (Input Validation): input do usuário limitado a 500 chars e
 *            renderizado apenas como textContent (nunca innerHTML).
 *  - CWE-312 (Sensitive Exposure): a chave da API nunca está aqui; a chamada
 *            passa obrigatoriamente pelo proxy server-side (/api/chat).
 *  - CWE-1022 (Open Redirect): links gerados pela IA recebem
 *             rel="noopener noreferrer" via hook do DOMPurify.
 *  - Rate limit client-side: máx. RL_MAX mensagens por RL_WINDOW ms,
 *    sem guardar estado no servidor para esta camada.
 *
 * Funções globais expostas (chamadas inline no HTML):
 *  - toggleChat()
 *  - sendMessage()
 *  - sendSuggestion(text)
 *
 * @project  Infinity Web — Site institucional
 * @version  2.0.0
 */

(function () {
  'use strict';

  /* =====================================================================
     CONSTANTES DE CONFIGURAÇÃO
  ===================================================================== */

  /** URL do proxy server-side que repassa a mensagem à API Groq. */
  var PROXY_URL = '/api/chat';

  /**
   * Configuração do DOMPurify para saídas do bot.
   * Permite apenas tags de formatação seguras.
   * @type {object}
   */
  var PURIFY_CONFIG = {
    ALLOWED_TAGS: ['b', 'strong', 'em', 'br', 'ul', 'ol', 'li', 'a', 'p'],
    ALLOWED_ATTR: ['href', 'target', 'rel'],
    FORCE_BODY: true,
  };

  // Garante que links gerados pela IA sejam seguros (CWE-1022)
  DOMPurify.addHook('afterSanitizeAttributes', function (node) {
    if (node.tagName === 'A') {
      node.setAttribute('target', '_blank');
      node.setAttribute('rel', 'noopener noreferrer');
    }
  });

  /* =====================================================================
     RATE LIMITING CLIENT-SIDE
     Limita a RL_MAX mensagens por RL_WINDOW milissegundos para
     proteger a cota da API e evitar flooding acidental.
  ===================================================================== */

  /** Número máximo de mensagens por janela de tempo */
  var RL_MAX    = 5;

  /** Janela de tempo do rate limit em milissegundos (60 segundos) */
  var RL_WINDOW = 60_000;

  /** Array com timestamps das mensagens enviadas na janela atual */
  var msgTimestamps = [];

  /**
   * Verifica se o usuário atingiu o limite de envios.
   * Remove timestamps fora da janela antes de verificar.
   *
   * @returns {boolean} true se o limite foi atingido, false caso contrário.
   */
  function isRateLimited() {
    var now = Date.now();

    // Remove timestamps expirados
    while (msgTimestamps.length && now - msgTimestamps[0] > RL_WINDOW) {
      msgTimestamps.shift();
    }

    if (msgTimestamps.length >= RL_MAX) return true;

    msgTimestamps.push(now);
    return false;
  }

  /* =====================================================================
     ESTADO DO WIDGET
  ===================================================================== */

  /** Indica se a janela do chat está aberta */
  var chatOpen = false;

  /* =====================================================================
     FUNÇÕES DE CONTROLE DA JANELA
  ===================================================================== */

  /**
   * Alterna a visibilidade do widget de chat.
   * Troca o ícone (robô ↔ X) e oculta a notificação quando aberto.
   *
   * @returns {void}
   */
  function toggleChat() {
    chatOpen = !chatOpen;

    var win   = document.getElementById('chatWindow');
    var icon  = document.getElementById('chatIcon');
    var notif = document.getElementById('chatNotif');

    win.classList.toggle('open', chatOpen);
    icon.className = chatOpen ? 'fas fa-times' : 'fas fa-robot';

    if (chatOpen) {
      notif.style.display = 'none';
      scrollMessages();
    }
  }

  /**
   * Rola a área de mensagens até o final (mensagem mais recente).
   * Usa setTimeout para aguardar a renderização do DOM.
   *
   * @returns {void}
   */
  function scrollMessages() {
    var msgs = document.getElementById('chatMessages');
    setTimeout(function () {
      msgs.scrollTop = msgs.scrollHeight;
    }, 100);
  }

  /* =====================================================================
     RENDERIZAÇÃO DE MENSAGENS
  ===================================================================== */

  /**
   * Converte Markdown básico em HTML seguro (antes de passar pelo DOMPurify).
   *
   * Suporte:
   *  - **negrito** → <strong>negrito</strong>
   *  - *itálico*  → <em>itálico</em>
   *  - Linhas iniciadas com "- " ou "• " → <ul><li>...</li></ul>
   *  - Quebras de linha → <br>
   *
   * Os caracteres HTML são escapados ANTES de aplicar as substituições
   * de Markdown para evitar injeção de tags via texto da API.
   *
   * @param   {string} text - Texto em Markdown vindo da IA.
   * @returns {string}      - HTML com formatação básica.
   */
  function markdownToHtml(text) {
    return text
      // Escapa entidades HTML antes de qualquer substituição (CWE-79)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      // Negrito e itálico
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.+?)\*/g,     '<em>$1</em>')
      // Itens de lista
      .replace(/^[-•]\s+(.+)$/gm, '<li>$1</li>')
      .replace(/(<li>[\s\S]+?<\/li>)/g, '<ul>$1</ul>')
      // Quebras de linha
      .replace(/\n/g, '<br>');
  }

  /**
   * Adiciona uma mensagem (do bot ou do usuário) na área de chat.
   *
   * Segurança:
   *  - Mensagens do bot: HTML processado por markdownToHtml() e depois
   *    sanitizado por DOMPurify antes de usar innerHTML.
   *  - Mensagens do usuário: sempre inseridas via textContent (sem interpretação HTML).
   *
   * @param {string} text - Conteúdo da mensagem.
   * @param {string} type - 'bot' ou 'user'.
   * @returns {void}
   */
  function addMessage(text, type) {
    var container = document.getElementById('chatMessages');

    var wrapper = document.createElement('div');
    wrapper.className = 'msg ' + type;

    var bubble = document.createElement('div');
    bubble.className = 'msg-bubble';

    if (type === 'bot') {
      // Sanitiza HTML antes de exibir — previne XSS de respostas da IA (CWE-79)
      bubble.innerHTML = DOMPurify.sanitize(markdownToHtml(text), PURIFY_CONFIG);
    } else {
      // Usuário: textContent garante que nenhuma tag seja interpretada
      bubble.textContent = text;
    }

    var avatar = document.createElement('div');
    avatar.className  = 'msg-avatar';
    avatar.textContent = type === 'bot' ? '🤖' : '👤';

    wrapper.appendChild(avatar);
    wrapper.appendChild(bubble);
    container.appendChild(wrapper);

    scrollMessages();
  }

  /* =====================================================================
     INDICADOR DE DIGITAÇÃO
  ===================================================================== */

  /**
   * Exibe o indicador de três pontos animados enquanto a IA processa.
   * @returns {void}
   */
  function showTyping() {
    var container = document.getElementById('chatMessages');

    var wrapper = document.createElement('div');
    wrapper.className = 'msg bot';
    wrapper.id = 'typingIndicator';
    wrapper.innerHTML = [
      '<div class="msg-avatar">🤖</div>',
      '<div class="typing-indicator">',
        '<div class="typing-dot"></div>',
        '<div class="typing-dot"></div>',
        '<div class="typing-dot"></div>',
      '</div>',
    ].join('');

    container.appendChild(wrapper);
    scrollMessages();
  }

  /**
   * Remove o indicador de digitação do DOM.
   * @returns {void}
   */
  function removeTyping() {
    var el = document.getElementById('typingIndicator');
    if (el) el.remove();
  }

  /* =====================================================================
     COMUNICAÇÃO COM O PROXY GROQ
  ===================================================================== */

  /**
   * Envia a mensagem do usuário ao proxy server-side e retorna a resposta da IA.
   *
   * A chave da API Groq NUNCA transita pelo frontend (CWE-312).
   * O proxy (groq-proxy.php ou netlify/functions/groq-proxy.js) é
   * responsável por autenticar com a Groq e retornar apenas o texto.
   *
   * @async
   * @param   {string} userText - Mensagem sanitizada do usuário.
   * @returns {Promise<string>} - Texto da resposta da IA.
   * @throws  {Error} Se a resposta HTTP não for 2xx ou o payload for inválido.
   */
  async function callGroq(userText) {
    var response = await fetch(PROXY_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ message: userText }),
    });

    if (!response.ok) {
      var err = await response.json().catch(function () { return {}; });
      throw new Error(err.error || 'HTTP ' + response.status);
    }

    var data = await response.json();
    if (!data.reply) throw new Error('Resposta vazia da IA');

    return data.reply;
  }

  /* =====================================================================
     ENVIO DE MENSAGEM
  ===================================================================== */

  /**
   * Lê o input do usuário, valida, exibe na UI e despacha para a IA.
   *
   * Fluxo:
   *  1. Lê e sanitiza o texto do input (máx. 500 chars).
   *  2. Verifica o rate limit; exibe aviso se atingido.
   *  3. Exibe a mensagem do usuário + indicador de digitação.
   *  4. Chama o proxy Groq e exibe a resposta.
   *  5. Reabilita o input independentemente de sucesso ou erro.
   *
   * @returns {Promise<void>}
   */
  async function sendMessage() {
    var input   = document.getElementById('chatInput');
    var rawText = input.value.trim();

    if (!rawText) return;

    // Sanitiza e limita o comprimento (CWE-20)
    var text = rawText.slice(0, 500);
    input.value = '';

    // Oculta os chips de sugestão após a primeira mensagem real
    var suggestions = document.getElementById('chatSuggestions');
    if (suggestions) suggestions.style.display = 'none';

    // Feedback de rate limit — evita enviar a requisição (protege cota da API)
    if (isRateLimited()) {
      addMessage(text, 'user');
      addMessage('⏳ Você enviou muitas mensagens em pouco tempo. Aguarde um momento e tente novamente!', 'bot');
      return;
    }

    addMessage(text, 'user');
    showTyping();

    // Desabilita input durante a chamada assíncrona
    input.disabled = true;
    document.querySelector('.chat-send').disabled = true;

    try {
      var reply = await callGroq(text);
      removeTyping();
      addMessage(reply, 'bot');
    } catch (err) {
      removeTyping();
      // Mensagem de erro genérica ao usuário; detalhes vão apenas para o console (CWE-209)
      console.error('[Infinity AI]', err.message);
      addMessage(
        '⚠️ Não consegui me conectar à IA agora. Tente novamente em instantes ou fale conosco pelo WhatsApp **(11) 96401-2136**.',
        'bot'
      );
    } finally {
      input.disabled = false;
      document.querySelector('.chat-send').disabled = false;
      input.focus();
    }
  }

  /**
   * Preenche o input com um texto de sugestão e o envia automaticamente.
   * Chamado pelos chips de sugestão rápida no widget.
   *
   * @param {string} text - Texto da sugestão selecionada.
   * @returns {void}
   */
  function sendSuggestion(text) {
    var input = document.getElementById('chatInput');
    input.value = text;
    sendMessage();
  }

  /* =====================================================================
     EXPOSIÇÃO PÚBLICA
     Funções que precisam ser acessíveis via atributos onclick no HTML.
  ===================================================================== */
  window.toggleChat    = toggleChat;
  window.sendMessage   = sendMessage;
  window.sendSuggestion = sendSuggestion;

  /* =====================================================================
     INICIALIZAÇÃO — Efeito de atenção após 4 segundos
     Pulsa a notificação para indicar que o chat está disponível.
  ===================================================================== */
  document.addEventListener('DOMContentLoaded', function () {
    setTimeout(function () {
      if (!chatOpen) {
        var notif = document.getElementById('chatNotif');
        if (notif) notif.style.animation = 'ring-pulse 1s ease-in-out 3';
      }
    }, 4000);
  });

})();
