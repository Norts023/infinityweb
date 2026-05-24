/**
 * @file plans.js
 * @description Controla as abas (tabs) da seção de Planos,
 *              alternando a visibilidade entre os grids
 *              Residencial, Condomínios e Empresarial.
 *
 * Dependências: Nenhuma (Vanilla JS puro)
 * Relacionado:  assets/css/sections.css (.plans-tabs, .plans-grid)
 *
 * Uso no HTML (chamada inline nos botões de tab):
 *   <button class="tab-btn active" onclick="setTab(this, 'residencial')">Para Você</button>
 *
 * IDs dos grids de planos esperados no DOM:
 *   #tab-residencial | #tab-condominios | #tab-empresarial
 *
 * @project  Infinity Web — Site institucional
 * @version  2.0.0
 */

/** IDs de todos os painéis de planos existentes na página */
var PLAN_TAB_IDS = ['residencial', 'condominios', 'empresarial'];

/**
 * Alterna a aba de planos ativa.
 *
 * Ao ser chamada:
 *  1. Remove a classe .active de todos os botões de tab.
 *  2. Adiciona .active ao botão clicado.
 *  3. Oculta todos os grids de planos (display: none).
 *  4. Exibe o grid correspondente ao tabId (display: grid).
 *
 * @param {HTMLElement} btn   - O botão de tab clicado.
 * @param {string}      tabId - ID da tab a exibir ('residencial' | 'condominios' | 'empresarial').
 * @returns {void}
 *
 * @example
 * // No HTML:
 * <button onclick="setTab(this, 'empresarial')">Empresarial</button>
 */
function setTab(btn, tabId) {
  // Remove o estado ativo de todos os botões
  document.querySelectorAll('.tab-btn').forEach(function (b) {
    b.classList.remove('active');
  });

  // Ativa o botão clicado
  btn.classList.add('active');

  // Alterna a visibilidade dos grids
  PLAN_TAB_IDS.forEach(function (id) {
    var panel = document.getElementById('tab-' + id);
    if (panel) {
      panel.style.display = (id === tabId) ? 'grid' : 'none';
    }
  });
}
