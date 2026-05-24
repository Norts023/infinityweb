<?php
/**
 * @file includes/helpers.php
 * @description Funções utilitárias genéricas: escape de output,
 *              leitura/escrita de JSON e geração/verificação de CSRF tokens.
 *
 * Depende de:  includes/config.php (nenhuma dependência direta, mas requer
 *              que a sessão esteja iniciada antes de chamar csrfToken/verifyCsrf)
 *
 * Funções exportadas:
 *  e()          — Escape de string para saída HTML segura
 *  readJson()   — Lê e decodifica um arquivo JSON
 *  writeJson()  — Serializa e grava dados em um arquivo JSON
 *  csrfToken()  — Retorna (ou cria) o token CSRF da sessão atual
 *  verifyCsrf() — Verifica o token CSRF do POST; encerra com 403 se inválido
 *
 * @project  Infinity Web — Painel Administrativo
 * @version  2.0.0
 */

/* =====================================================================
   SAÍDA SEGURA
===================================================================== */

/**
 * Escapa uma string para exibição segura em HTML (previne XSS — CWE-79).
 *
 * Usa ENT_QUOTES para escapar também aspas simples (importante em atributos HTML)
 * e ENT_SUBSTITUTE para substituir sequências UTF-8 inválidas.
 *
 * @param  string $s  Valor bruto a ser escapado.
 * @return string     Valor seguro para uso em contexto HTML.
 *
 * @example
 *   echo e($userInput); // nunca echo $userInput diretamente
 */
function e(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/* =====================================================================
   PERSISTÊNCIA JSON
===================================================================== */

/**
 * Lê e decodifica um arquivo JSON.
 *
 * Retorna $default caso o arquivo não exista ou o JSON seja inválido,
 * evitando exceções em caso de arquivo corrompido ou ainda não criado.
 *
 * @param  string $path     Caminho absoluto do arquivo.
 * @param  mixed  $default  Valor de retorno em caso de falha (padrão: []).
 * @return mixed            Array/objeto decodificado ou $default.
 */
function readJson(string $path, $default = [])
{
    if (!file_exists($path)) {
        return $default;
    }

    $data = json_decode(file_get_contents($path), true);

    return (json_last_error() === JSON_ERROR_NONE) ? $data : $default;
}

/**
 * Serializa $data em JSON e grava no $path com lock exclusivo.
 *
 * O flag LOCK_EX garante que somente um processo escreva por vez,
 * prevenindo condições de corrida em ambientes com múltiplas requisições.
 * JSON_UNESCAPED_UNICODE mantém caracteres especiais (acentos) legíveis.
 *
 * @param  string $path  Caminho absoluto do arquivo de destino.
 * @param  mixed  $data  Dados a serializar (array ou objeto).
 * @return void
 */
function writeJson(string $path, $data): void
{
    file_put_contents(
        $path,
        json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE),
        LOCK_EX
    );
}

/* =====================================================================
   CSRF (Cross-Site Request Forgery)
   Proteção contra requisições forjadas em formulários de estado.
   Requer que session_start() tenha sido chamado anteriormente.
===================================================================== */

/**
 * Retorna o token CSRF da sessão atual, criando um novo se necessário.
 *
 * O token é gerado com random_bytes(32) e codificado em hex — 64 caracteres
 * de alta entropia, resistente a ataques de força bruta.
 *
 * @return string Token CSRF em formato hexadecimal (64 chars).
 */
function csrfToken(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf'];
}

/**
 * Verifica o token CSRF enviado no POST.
 *
 * Usa hash_equals() para comparação em tempo constante, prevenindo
 * ataques de timing (timing attack — CWE-208).
 * Encerra a execução com HTTP 403 se o token for inválido ou ausente.
 *
 * @return void
 */
function verifyCsrf(): void
{
    $token = $_POST['csrf'] ?? '';

    if (!hash_equals($_SESSION['csrf'] ?? '', $token)) {
        http_response_code(403);
        die('Token CSRF inválido.');
    }
}
