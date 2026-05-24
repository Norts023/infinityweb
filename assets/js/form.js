/**
 * @file form.js
 * @description Controla o envio do formulário de contato da seção #contato.
 *
 * Dependências: Nenhuma (Vanilla JS puro)
 * Relacionado:  assets/css/sections.css (.contact-form-wrap, .form-submit)
 *
 * Comportamento atual:
 *  - Intercepta o submit do formulário (preventDefault).
 *  - Fornece feedback visual ao usuário (botão muda para "Enviado!").
 *  - Reseta o formulário após 3 segundos.
 *
 * Integração futura:
 *  Para enviar os dados de fato, substitua o corpo de submitForm() por
 *  uma chamada fetch() para seu endpoint de backend (PHP, Netlify Forms, etc.).
 *  Exemplo:
 *    fetch('/api/contact', { method: 'POST', body: new FormData(e.target) })
 *      .then(r => r.ok ? showSuccess() : showError())
 *      .catch(showError);
 *
 * Uso no HTML (chamada inline no form):
 *   <form onsubmit="submitForm(event)">
 *
 * @project  Infinity Web — Site institucional
 * @version  2.0.0
 */

/**
 * Trata o envio do formulário de contato com feedback visual.
 *
 * @param {SubmitEvent} event - O evento de submit do formulário.
 * @returns {void}
 */
function submitForm(event) {
  event.preventDefault();

  var form      = event.target;
  var submitBtn = form.querySelector('.form-submit');

  if (!submitBtn) return;

  // ── Feedback visual de sucesso ──────────────────────────────────────────
  var originalHTML  = submitBtn.innerHTML;
  var originalBg    = submitBtn.style.background;

  submitBtn.innerHTML    = '<i class="fas fa-check"></i> Mensagem enviada!';
  submitBtn.style.background = '#16a34a'; // verde de confirmação
  submitBtn.disabled     = true;

  // ── Restaura o botão e limpa o formulário após 3 segundos ──────────────
  setTimeout(function () {
    submitBtn.innerHTML    = originalHTML;
    submitBtn.style.background = originalBg;
    submitBtn.disabled     = false;
    form.reset();
  }, 3000);
}
