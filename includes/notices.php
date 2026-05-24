<?php
/**
 * @file includes/notices.php
 * @description CRUD de avisos/alertas de rede.
 *
 * Responsabilidades:
 *  - Criar novos avisos com validação e sanitização de campos
 *  - Alternar o status ativo/inativo de um aviso
 *  - Excluir avisos pelo ID
 *  - Expor os metadados de tipos, prioridades e regiões disponíveis
 *
 * Depende de:
 *  - includes/config.php  (NOTICES_FILE)
 *  - includes/helpers.php (readJson, writeJson, verifyCsrf)
 *  - Sessão PHP iniciada e isLoggedIn() disponível (de auth.php)
 *
 * Funções exportadas:
 *  handleCreateNotice()  — Processa POST de criação de aviso
 *  handleToggleNotice()  — Alterna ativo/inativo via GET
 *  handleDeleteNotice()  — Remove aviso via GET
 *  getNoticesMeta()      — Retorna arrays de tipos, prioridades e regiões
 *
 * @project  Infinity Web — Painel Administrativo
 * @version  2.0.0
 */

/* =====================================================================
   METADADOS — Listas de opções para formulários
===================================================================== */

/**
 * Retorna os arrays de metadados usados nos selects do formulário
 * de criação de aviso e na exibição da lista de avisos.
 *
 * @return array{
 *   tipos:      array<string,string>,
 *   prioridades: array<string,string>,
 *   regioes:    string[]
 * }
 */
function getNoticesMeta(): array
{
    return [
        'tipos' => [
            'instabilidade' => '⚡ Instabilidade',
            'manutencao'    => '🔧 Manutenção',
            'queda'         => '🔴 Queda Total',
            'normalizado'   => '✅ Normalizado',
        ],
        'prioridades' => [
            'alta'  => 'Alta',
            'media' => 'Média',
            'baixa' => 'Baixa',
        ],
        'regioes' => [
            'Jordanesia',
            'Cajamar Centro',
            'Região Industrial',
            'Polvilho',
            'Todas as regiões',
            'Outra',
        ],
    ];
}

/* =====================================================================
   CRIAR AVISO
===================================================================== */

/**
 * Processa a criação de um novo aviso a partir dos dados do POST.
 *
 * Sanitização:
 *  - strip_tags() remove qualquer HTML dos campos de texto.
 *  - trim() limpa espaços desnecessários.
 *  - Campos obrigatórios (titulo, regiao, mensagem) são validados.
 *
 * O aviso é salvo como um item novo no array de NOTICES_FILE.
 * O ID único é gerado com uniqid() para evitar colisões.
 *
 * @return array{type: string, message: string}
 *         Retorna o tipo ('success'|'error') e a mensagem de feedback.
 */
function handleCreateNotice(): array
{
    verifyCsrf();

    $titulo     = trim(strip_tags($_POST['titulo']     ?? ''));
    $regiao     = trim(strip_tags($_POST['regiao']     ?? ''));
    $tipo       = trim(strip_tags($_POST['tipo']       ?? ''));
    $mensagem   = trim(strip_tags($_POST['mensagem']   ?? ''));
    $prioridade = trim(strip_tags($_POST['prioridade'] ?? 'media'));
    $expira     = $_POST['expira'] ?? '';

    if (!$titulo || !$regiao || !$mensagem) {
        return ['type' => 'error', 'message' => 'Preencha título, região e mensagem.'];
    }

    $notices   = readJson(NOTICES_FILE, []);
    $notices[] = [
        'id'         => uniqid('n_', true),
        'titulo'     => $titulo,
        'regiao'     => $regiao,
        'tipo'       => $tipo ?: 'instabilidade',
        'mensagem'   => $mensagem,
        'prioridade' => $prioridade,
        'ativo'      => true,
        'criado_em'  => date('Y-m-d H:i:s'),
        'expira_em'  => $expira ?: null,
    ];

    writeJson(NOTICES_FILE, $notices);

    return ['type' => 'success', 'message' => '✅ Aviso criado e ativado com sucesso!'];
}

/* =====================================================================
   ALTERNAR STATUS (ATIVO / INATIVO)
===================================================================== */

/**
 * Alterna o campo 'ativo' de um aviso identificado pelo ID na query string.
 * Redireciona para o dashboard após a operação.
 *
 * @param  string $id  ID do aviso a alternar (vem de $_GET['id']).
 * @return void
 */
function handleToggleNotice(string $id): void
{
    $notices = readJson(NOTICES_FILE, []);

    foreach ($notices as &$n) {
        if ($n['id'] === $id) {
            $n['ativo'] = !$n['ativo'];
            break;
        }
    }
    unset($n); // desfaz a referência do foreach

    writeJson(NOTICES_FILE, $notices);

    header('Location: admin.php?action=dashboard&msg=toggled');
    exit;
}

/* =====================================================================
   EXCLUIR AVISO
===================================================================== */

/**
 * Remove permanentemente um aviso pelo ID.
 * Redireciona para o dashboard após a exclusão.
 *
 * @param  string $id  ID do aviso a excluir (vem de $_GET['id']).
 * @return void
 */
function handleDeleteNotice(string $id): void
{
    $notices = readJson(NOTICES_FILE, []);
    $notices = array_values(
        array_filter($notices, fn($n) => $n['id'] !== $id)
    );

    writeJson(NOTICES_FILE, $notices);

    header('Location: admin.php?action=dashboard&msg=deleted');
    exit;
}
