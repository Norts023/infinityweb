/**
 * @file animations.js
 * @description Animações visuais da página disparadas por scroll
 *              (Intersection Observer API).
 *
 * Dependências: Nenhuma (Vanilla JS puro)
 * Relacionado:  assets/css/sections.css (.speed-num, .hero)
 *
 * Animações implementadas:
 *  1. Counter do card de velocidade no Hero
 *     — Conta de 0 até TARGET_SPEED (650 Mbps) quando o hero
 *       entra na viewport, simulando um "teste de velocidade".
 *
 * @project  Infinity Web — Site institucional
 * @version  2.0.0
 */

(function () {
  'use strict';

  /** Velocidade máxima exibida no card (Mbps) */
  var TARGET_SPEED = 650;

  /** Duração aproximada da animação (ms) — 60 frames @ 16ms/frame */
  var ANIMATION_FRAMES = 60;

  // ─── Inicializa após o DOM estar pronto ──────────────────────────────────
  document.addEventListener('DOMContentLoaded', function () {
    initSpeedCounter();
  });

  /* =====================================================================
     SPEED COUNTER — Animação do card de velocidade no Hero
  ===================================================================== */

  /**
   * Configura o Intersection Observer que dispara a animação
   * do contador de velocidade quando o hero entra na viewport.
   * O observer é desconectado após a primeira exibição para
   * evitar que o contador reinicie a cada scroll.
   * @returns {void}
   */
  function initSpeedCounter() {
    var heroEl = document.querySelector('.hero');

    if (!heroEl) return;

    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          animateCounter();
          observer.disconnect(); // Executa apenas uma vez
        }
      });
    }, { threshold: 0.3 });

    observer.observe(heroEl);
  }

  /**
   * Anima o contador do elemento #speedCounter de 0 até TARGET_SPEED.
   *
   * Algoritmo:
   *  - Calcula o incremento por frame com base no total de frames desejado.
   *  - Usa setInterval a ~60 fps (16 ms por frame).
   *  - Para quando o valor atinge ou ultrapassa TARGET_SPEED.
   *
   * @returns {void}
   */
  function animateCounter() {
    var el = document.getElementById('speedCounter');

    if (!el) return;

    var current   = 0;
    var increment = Math.ceil(TARGET_SPEED / ANIMATION_FRAMES);

    var interval = setInterval(function () {
      current = Math.min(current + increment, TARGET_SPEED);
      el.textContent = current;

      if (current >= TARGET_SPEED) {
        clearInterval(interval);
      }
    }, 16);
  }

})();
