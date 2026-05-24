/**
 * @file navigation.js
 * @description Controle de navegação global da página:
 *              menu hamburger (mobile), smooth scroll para âncoras
 *              e visibilidade do botão "voltar ao topo".
 *
 * Dependências: Nenhuma (Vanilla JS puro)
 * Relacionado:  assets/css/layout.css (.hamburger, .mobile-menu, .scroll-top)
 *
 * Funções exportadas (escopo global para uso inline no HTML):
 *  — Nenhuma. Todos os handlers são registrados via addEventListener.
 *
 * @project  Infinity Web — Site institucional
 * @version  2.0.0
 */

(function () {
  'use strict';

  // ─── Aguarda o DOM estar completamente carregado ──────────────────────────
  document.addEventListener('DOMContentLoaded', function () {
    initHamburger();
    initScrollTop();
    initSmoothScroll();
  });

  /* =====================================================================
     HAMBURGER MENU
     Alterna as classes .open no botão e no menu mobile quando clicado.
     Fecha automaticamente quando o usuário clica em qualquer link.
  ===================================================================== */

  /**
   * Inicializa o comportamento do menu hamburger.
   * @returns {void}
   */
  function initHamburger() {
    const hamburger  = document.getElementById('hamburger');
    const mobileMenu = document.getElementById('mobileMenu');

    if (!hamburger || !mobileMenu) return;

    // Alterna o estado aberto/fechado ao clicar no ícone
    hamburger.addEventListener('click', function () {
      hamburger.classList.toggle('open');
      mobileMenu.classList.toggle('open');
    });

    // Fecha o menu ao clicar em qualquer link interno
    mobileMenu.querySelectorAll('a').forEach(function (link) {
      link.addEventListener('click', function () {
        hamburger.classList.remove('open');
        mobileMenu.classList.remove('open');
      });
    });
  }

  /* =====================================================================
     BOTÃO "VOLTAR AO TOPO"
     Torna-se visível quando o usuário scrollar mais de 400 px.
     Ao clicar, faz scroll suave até o topo da página.
  ===================================================================== */

  /**
   * Inicializa o botão de scroll-to-top.
   * A classe .visible (definida em sections.css) controla a opacidade.
   * @returns {void}
   */
  function initScrollTop() {
    const scrollTopBtn = document.getElementById('scrollTop');

    if (!scrollTopBtn) return;

    // Mostra/oculta o botão conforme a posição do scroll
    window.addEventListener('scroll', function () {
      scrollTopBtn.classList.toggle('visible', window.scrollY > 400);
    });

    // O onclick está definido inline no HTML para clareza visual; a
    // lógica de scroll também poderia ser movida para cá se necessário.
  }

  /* =====================================================================
     SMOOTH SCROLL PARA ÂNCORAS
     Intercepta cliques em links que apontam para IDs internos (#secao)
     e substitui o salto abrupto por uma rolagem suave.
  ===================================================================== */

  /**
   * Adiciona scroll suave para todos os links de âncora internos.
   * @returns {void}
   */
  function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(function (anchor) {
      anchor.addEventListener('click', function (event) {
        const targetId = anchor.getAttribute('href');
        const target   = document.querySelector(targetId);

        if (target) {
          event.preventDefault();
          target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      });
    });
  }

})();
