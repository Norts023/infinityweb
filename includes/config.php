<?php
/**
 * @file includes/config.php
 * @description Constantes de configuração centralizadas do painel administrativo.
 *
 * Este arquivo deve ser incluído PRIMEIRO por admin.php e por qualquer
 * outro script PHP que precise acessar os caminhos ou limites definidos aqui.
 *
 * Não contém lógica de execução — apenas constantes (define).
 *
 * @project  Infinity Web — Painel Administrativo
 * @version  2.0.0
 */

// ─── Caminhos de dados ───────────────────────────────────────────────────────

/** Diretório onde os arquivos JSON de dados são armazenados */
define('DATA_DIR',      __DIR__ . '/../data/');

/** Arquivo de avisos/alertas exibidos na IA e no painel */
define('NOTICES_FILE',  DATA_DIR . 'notices.json');

/** Arquivo de configuração do admin (hash da senha) */
define('CONFIG_FILE',   DATA_DIR . 'admin-config.json');

/** Arquivo de controle de rate limiting de tentativas de login */
define('LOGIN_RL_FILE', DATA_DIR . 'login-rl.json');

// ─── Limites de segurança ────────────────────────────────────────────────────

/** Número máximo de tentativas de login antes do bloqueio por IP */
define('LOGIN_MAX_ATTEMPTS', 5);

/** Tempo de bloqueio em segundos após atingir LOGIN_MAX_ATTEMPTS (5 minutos) */
define('LOGIN_LOCKOUT_SEC', 300);
