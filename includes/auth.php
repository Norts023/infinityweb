<?php
/**
 * @file includes/auth.php
 * @description Autenticação de administrador e rate limiting de login.
 *
 * Depende de:
 *  - includes/config.php  (LOGIN_RL_FILE, LOGIN_MAX_ATTEMPTS, LOGIN_LOCKOUT_SEC)
 *  - includes/helpers.php (readJson, writeJson)
 *  - Sessão PHP iniciada (session_start já chamado em admin.php)
 *
 * Funções exportadas:
 *  isLoggedIn()           — Verifica se o admin está autenticado
 *  requireLogin()         — Redireciona para login se não autenticado
 *  checkLoginRateLimit()  — Verifica se o IP pode tentar login
 *  recordFailedLogin()    — Registra tentativa falha e aplica bloqueio se necessário
 *  clearLoginRateLimit()  — Limpa o registro de tentativas após login bem-sucedido
 *
 * Segurança implementada:
 *  - Senhas armazenadas como bcrypt (password_hash / password_verify) — CWE-916
 *  - Rate limiting por IP — bloqueia força bruta após LOGIN_MAX_ATTEMPTS tentativas
 *  - Delay artificial (usleep) após senha incorreta — dificulta enumeração de timing
 *  - Regeneração do ID de sessão após login bem-sucedido — previne session fixation
 *
 * @project  Infinity Web — Painel Administrativo
 * @version  2.0.0
 */

/* =====================================================================
   VERIFICAÇÃO DE AUTENTICAÇÃO
===================================================================== */

/**
 * Verifica se o administrador está autenticado na sessão atual.
 *
 * @return bool true se logado, false caso contrário.
 */
function isLoggedIn(): bool
{
    return !empty($_SESSION['admin_logged_in']);
}

/**
 * Redireciona para a tela de login caso o usuário não esteja autenticado.
 * Encerra a execução após o redirecionamento.
 *
 * @return void
 */
function requireLogin(): void
{
    if (!isLoggedIn()) {
        header('Location: admin.php');
        exit;
    }
}

/* =====================================================================
   RATE LIMITING DE LOGIN
   Estado persistido em LOGIN_RL_FILE (JSON) para sobreviver entre requisições.
   Chave do registro: md5 do IP (evita armazenar IPs em texto puro).
===================================================================== */

/**
 * Verifica se o IP atual está bloqueado por excesso de tentativas de login.
 *
 * Limpa automaticamente entradas cujo período de observação expirou,
 * permitindo que o IP tente novamente após LOGIN_LOCKOUT_SEC segundos.
 *
 * @return bool true se o IP pode tentar, false se está bloqueado.
 */
function checkLoginRateLimit(): bool
{
    $ip   = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $data = readJson(LOGIN_RL_FILE, []);
    $now  = time();
    $key  = md5($ip);

    if (isset($data[$key])) {
        $entry = $data[$key];

        // IP ainda no período de bloqueio
        if ($entry['locked_until'] > $now) {
            return false;
        }

        // Período de observação expirou — remove o registro
        if (($now - $entry['first_attempt']) > LOGIN_LOCKOUT_SEC) {
            unset($data[$key]);
            writeJson(LOGIN_RL_FILE, $data);
        }
    }

    return true;
}

/**
 * Registra uma tentativa de login falha para o IP atual.
 * Aplica bloqueio temporário se LOGIN_MAX_ATTEMPTS for atingido.
 *
 * @return void
 */
function recordFailedLogin(): void
{
    $ip   = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $data = readJson(LOGIN_RL_FILE, []);
    $now  = time();
    $key  = md5($ip);

    if (!isset($data[$key])) {
        $data[$key] = [
            'attempts'      => 0,
            'first_attempt' => $now,
            'locked_until'  => 0,
        ];
    }

    $data[$key]['attempts']++;

    // Aplica bloqueio ao atingir o limite de tentativas
    if ($data[$key]['attempts'] >= LOGIN_MAX_ATTEMPTS) {
        $data[$key]['locked_until'] = $now + LOGIN_LOCKOUT_SEC;
    }

    writeJson(LOGIN_RL_FILE, $data);
}

/**
 * Remove o registro de tentativas falhas do IP após login bem-sucedido.
 * Deve ser chamado junto com session_regenerate_id() após autenticação.
 *
 * @return void
 */
function clearLoginRateLimit(): void
{
    $ip   = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $data = readJson(LOGIN_RL_FILE, []);

    unset($data[md5($ip)]);
    writeJson(LOGIN_RL_FILE, $data);
}
