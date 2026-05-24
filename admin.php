<?php
/**
 * @file admin.php
 * @description Painel administrativo da Infinity Web — ponto de entrada único.
 *
 * Este arquivo é responsável apenas por:
 *  1. Inicializar a sessão segura
 *  2. Incluir os módulos de lógica (config, helpers, auth, notices)
 *  3. Despachar as ações recebidas via GET/POST
 *  4. Renderizar a view correspondente (setup | login | dashboard | settings)
 *
 * Toda lógica de negócio está nos includes:
 *  includes/config.php   → Constantes de configuração
 *  includes/helpers.php  → e(), readJson(), writeJson(), csrfToken(), verifyCsrf()
 *  includes/auth.php     → isLoggedIn(), requireLogin(), rate limit de login
 *  includes/notices.php  → CRUD de avisos e metadados
 *
 * Segurança:
 *  - Sessão com httpOnly, SameSite=Strict, sem exposição via JS
 *  - CSRF token em todos os formulários de estado (POST)
 *  - Rate limiting de login por IP (5 tentativas / 5 minutos)
 *  - Senhas em bcrypt (password_hash / password_verify) — CWE-916
 *  - Todo output de dados escapado com e() (CWE-79)
 *  - Pasta /data inacessível via web (.htaccess)
 *
 * @project  Infinity Web — Painel Administrativo
 * @version  2.0.0
 */

// ─── Sessão segura ──────────────────────────────────────────────────────────
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'secure'   => false,   // Alterar para true em produção com HTTPS
    'httponly' => true,    // JavaScript não acessa o cookie (CWE-1004)
    'samesite' => 'Strict',
]);
session_start();

// ─── Módulos ────────────────────────────────────────────────────────────────
require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/notices.php';

// ─── Estado inicial ─────────────────────────────────────────────────────────
$action  = $_GET['action'] ?? 'dashboard';
$message = '';
$msgType = 'success';
$config  = readJson(CONFIG_FILE, []);
$isSetup = empty($config['password_hash']); // true se ainda não há senha definida

// ─── DESPACHO DE AÇÕES ──────────────────────────────────────────────────────

/**
 * SETUP INICIAL — Criação da senha de administrador.
 * Exibido apenas na primeira vez (quando CONFIG_FILE não tem password_hash).
 */
if ($isSetup && $_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'setup') {
    $pwd  = $_POST['password']  ?? '';
    $pwd2 = $_POST['password2'] ?? '';

    if (strlen($pwd) < 8) {
        $message = 'A senha deve ter pelo menos 8 caracteres.';
        $msgType = 'error';
    } elseif ($pwd !== $pwd2) {
        $message = 'As senhas não coincidem.';
        $msgType = 'error';
    } else {
        $config['password_hash'] = password_hash($pwd, PASSWORD_BCRYPT);
        writeJson(CONFIG_FILE, $config);
        $message = 'Senha configurada! Faça login para continuar.';
        $isSetup = false;
    }
}

/**
 * LOGIN — Verificação de credenciais com rate limiting.
 */
if (!$isSetup && !isLoggedIn() && $_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'login') {
    verifyCsrf();
    $pwd = $_POST['password'] ?? '';

    if (!checkLoginRateLimit()) {
        $message = 'Muitas tentativas. Aguarde 5 minutos.';
        $msgType = 'error';
    } elseif (password_verify($pwd, $config['password_hash'] ?? '')) {
        session_regenerate_id(true); // previne session fixation
        $_SESSION['admin_logged_in'] = true;
        clearLoginRateLimit();
        header('Location: admin.php?action=dashboard');
        exit;
    } else {
        recordFailedLogin();
        $message = 'Senha incorreta.';
        $msgType = 'error';
        usleep(400_000); // atraso artificial — dificulta brute-force por timing
    }
}

/** LOGOUT — Destrói a sessão e redireciona para a tela de login. */
if ($action === 'logout') {
    session_destroy();
    header('Location: admin.php');
    exit;
}

/** CRIAR AVISO — Requer autenticação; delega para notices.php. */
if (isLoggedIn() && $_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'create') {
    $result  = handleCreateNotice();
    $message = $result['message'];
    $msgType = $result['type'];
}

/** TOGGLE AVISO — Alterna ativo/inativo pelo ID na query string. */
if (isLoggedIn() && $action === 'toggle' && !empty($_GET['id'])) {
    handleToggleNotice($_GET['id']); // redireciona internamente
}

/** DELETAR AVISO — Remove pelo ID na query string. */
if (isLoggedIn() && $action === 'delete' && !empty($_GET['id'])) {
    handleDeleteNotice($_GET['id']); // redireciona internamente
}

/** TROCAR SENHA — Requer autenticação e verificação da senha atual. */
if (isLoggedIn() && $_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'change-password') {
    verifyCsrf();
    $atual = $_POST['atual'] ?? '';
    $nova  = $_POST['nova']  ?? '';
    $nova2 = $_POST['nova2'] ?? '';

    if (!password_verify($atual, $config['password_hash'] ?? '')) {
        $message = 'Senha atual incorreta.';
        $msgType = 'error';
    } elseif (strlen($nova) < 8) {
        $message = 'A nova senha deve ter pelo menos 8 caracteres.';
        $msgType = 'error';
    } elseif ($nova !== $nova2) {
        $message = 'As senhas não coincidem.';
        $msgType = 'error';
    } else {
        $config['password_hash'] = password_hash($nova, PASSWORD_BCRYPT);
        writeJson(CONFIG_FILE, $config);
        $message = '✅ Senha alterada com sucesso!';
    }
}

/** Mensagens vindas via query string (após redirecionamentos) */
if (empty($message) && !empty($_GET['msg'])) {
    $msgs    = ['toggled' => '🔄 Status do aviso atualizado.', 'deleted' => '🗑️ Aviso removido.'];
    $message = $msgs[$_GET['msg']] ?? '';
}

// ─── DADOS PARA A VIEW ───────────────────────────────────────────────────────
$notices   = readJson(NOTICES_FILE, []);
$ativos    = array_filter($notices, fn($n) => $n['ativo']);
$now       = date('Y-m-d H:i:s');
$expirados = array_filter($ativos, fn($n) => $n['expira_em'] && $n['expira_em'] < $now);

// Metadados de opções dos selects
$meta       = getNoticesMeta();
$tipos      = $meta['tipos'];
$prioridades = $meta['prioridades'];
$regioes    = $meta['regioes'];

?><!DOCTYPE html>
<!--
  admin.php — Painel administrativo da Infinity Web
  =================================================
  Módulos PHP incluídos:
    includes/config.php   → Constantes (caminhos, limites)
    includes/helpers.php  → e(), readJson(), writeJson(), csrfToken(), verifyCsrf()
    includes/auth.php     → isLoggedIn(), requireLogin(), rate limit
    includes/notices.php  → CRUD de avisos, getNoticesMeta()
-->
<html lang="pt-BR">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Admin — Infinity Web</title>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet"/>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"/>
  <style>
    /* ── Reset & Variáveis ───────────────────────────────────────── */
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --blue-900: #0a1628; --blue-800: #0d1f3c; --blue-700: #102a52;
      --blue-500: #1e4d9b; --blue-400: #2563c4; --blue-300: #4a90e2;
      --orange: #f97316; --orange-h: #ea6a0a;
      --green: #16a34a; --red: #dc2626; --yellow: #d97706;
      --white: #fff; --gray-50: #f8fafc; --gray-100: #f1f5f9;
      --gray-200: #e2e8f0; --gray-400: #94a3b8; --gray-600: #475569; --gray-800: #1e293b;
      --radius: 12px; --radius-sm: 8px;
      --shadow: 0 4px 20px rgba(0,0,0,.1);
      --transition: .2s ease;
    }
    body { font-family: 'Inter', sans-serif; background: var(--gray-100); color: var(--gray-800); min-height: 100vh; }
    a { text-decoration: none; color: inherit; }

    /* ── Topbar ─────────────────────────────────────────────────── */
    .topbar {
      background: var(--blue-900); color: rgba(255,255,255,.9);
      padding: 14px 24px;
      display: flex; align-items: center; justify-content: space-between;
    }
    .topbar-brand { display: flex; align-items: center; gap: 12px; font-weight: 800; font-size: 1.1rem; }
    .topbar-brand .icon { width: 36px; height: 36px; background: linear-gradient(135deg,var(--blue-400),var(--orange)); border-radius: 8px; display: grid; place-items: center; font-size: 1.1rem; }
    .topbar-brand span { color: var(--orange); }
    .topbar-right { display: flex; align-items: center; gap: 12px; }
    .topbar-right a { font-size: .85rem; color: rgba(255,255,255,.6); display: flex; align-items: center; gap: 6px; padding: 6px 12px; border-radius: 8px; transition: var(--transition); }
    .topbar-right a:hover { background: rgba(255,255,255,.1); color: #fff; }

    /* ── Layout principal ───────────────────────────────────────── */
    .layout { display: grid; grid-template-columns: 240px 1fr; min-height: calc(100vh - 64px); }

    /* ── Sidebar ────────────────────────────────────────────────── */
    .sidebar { background: var(--blue-800); padding: 24px 0; }
    .sidebar-label { font-size: .7rem; font-weight: 700; color: rgba(255,255,255,.3); text-transform: uppercase; letter-spacing: .08em; padding: 8px 24px 4px; }
    .sidebar a {
      display: flex; align-items: center; gap: 10px;
      padding: 10px 24px; color: rgba(255,255,255,.65); font-size: .88rem; font-weight: 500;
      transition: var(--transition); border-left: 3px solid transparent;
    }
    .sidebar a:hover,
    .sidebar a.active { color: #fff; background: rgba(255,255,255,.07); border-left-color: var(--orange); }
    .sidebar a i { width: 16px; color: var(--orange); }
    .sidebar-footer { padding: 24px; border-top: 1px solid rgba(255,255,255,.08); margin-top: 32px; }
    .sidebar-footer .label { font-size: .75rem; color: rgba(255,255,255,.3); margin-bottom: 8px; }
    .sidebar-footer .status { display: flex; align-items: center; gap: 6px; font-size: .82rem; color: rgba(255,255,255,.6); }
    .dot-online { width: 8px; height: 8px; background: #4ade80; border-radius: 50%; display: inline-block; }

    /* ── Área principal ─────────────────────────────────────────── */
    .main { padding: 32px; overflow-y: auto; }
    .page-header { margin-bottom: 28px; }
    .page-header h1 { font-size: 1.5rem; font-weight: 800; color: var(--blue-900); }
    .page-header p { color: var(--gray-600); font-size: .9rem; margin-top: 4px; }

    /* ── Cards de estatística ───────────────────────────────────── */
    .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 28px; }
    .stat-card { background: var(--white); border-radius: var(--radius); padding: 20px; border: 1px solid var(--gray-200); display: flex; align-items: center; gap: 16px; }
    .stat-icon { width: 48px; height: 48px; border-radius: 10px; display: grid; place-items: center; font-size: 1.3rem; flex-shrink: 0; }
    .si-total  { background: rgba(30,77,155,.1);  color: var(--blue-500); }
    .si-active { background: rgba(220,38,38,.1);  color: var(--red); }
    .si-ok     { background: rgba(22,163,74,.1);  color: var(--green); }
    .si-exp    { background: rgba(217,119,6,.1);  color: var(--yellow); }
    .stat-info .num { font-size: 1.8rem; font-weight: 900; line-height: 1; }
    .stat-info .lbl { font-size: .78rem; color: var(--gray-400); margin-top: 2px; }

    /* ── Cards de conteúdo ──────────────────────────────────────── */
    .card { background: var(--white); border-radius: var(--radius); border: 1px solid var(--gray-200); overflow: hidden; margin-bottom: 24px; }
    .card-header { padding: 16px 20px; border-bottom: 1px solid var(--gray-200); display: flex; align-items: center; justify-content: space-between; }
    .card-header h3 { font-size: 1rem; font-weight: 700; }
    .card-body { padding: 20px; }

    /* ── Formulários ────────────────────────────────────────────── */
    .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    .form-group { display: flex; flex-direction: column; gap: 6px; }
    .form-group.full { grid-column: span 2; }
    .form-group label { font-size: .82rem; font-weight: 600; color: var(--gray-600); }
    .form-group input,
    .form-group select,
    .form-group textarea {
      padding: 10px 14px; border: 2px solid var(--gray-200); border-radius: var(--radius-sm);
      font-family: inherit; font-size: .9rem; color: var(--gray-800); background: var(--white);
      transition: var(--transition); outline: none;
    }
    .form-group input:focus,
    .form-group select:focus,
    .form-group textarea:focus { border-color: var(--blue-400); box-shadow: 0 0 0 3px rgba(37,99,196,.1); }
    .form-group textarea { min-height: 80px; resize: vertical; }

    /* ── Botões ─────────────────────────────────────────────────── */
    .btn { display: inline-flex; align-items: center; gap: 7px; padding: 10px 20px; border-radius: var(--radius-sm); font-weight: 700; font-size: .88rem; cursor: pointer; border: none; transition: var(--transition); }
    .btn-primary { background: var(--blue-500); color: #fff; }
    .btn-primary:hover { background: var(--blue-400); }
    .btn-orange { background: var(--orange); color: #fff; }
    .btn-orange:hover { background: var(--orange-h); }
    .btn-sm { padding: 6px 12px; font-size: .78rem; }
    .btn-danger { background: rgba(220,38,38,.1); color: var(--red); }
    .btn-danger:hover { background: var(--red); color: #fff; }
    .btn-ghost { background: var(--gray-100); color: var(--gray-600); }
    .btn-ghost:hover { background: var(--gray-200); }
    .btn-full { width: 100%; justify-content: center; padding: 14px; font-size: .95rem; }

    /* ── Lista de avisos ────────────────────────────────────────── */
    .notice-list { display: flex; flex-direction: column; gap: 12px; }
    .notice-item { border: 1px solid var(--gray-200); border-radius: var(--radius-sm); padding: 16px; display: grid; grid-template-columns: 1fr auto; gap: 12px; align-items: start; transition: var(--transition); }
    .notice-item:hover { border-color: var(--blue-300); background: var(--gray-50); }
    .notice-item.inactive { opacity: .55; }
    .notice-top { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 6px; }
    .notice-title { font-weight: 700; font-size: .95rem; }
    .badge { display: inline-flex; align-items: center; gap: 4px; padding: 3px 10px; border-radius: 99px; font-size: .72rem; font-weight: 700; }
    .badge-active   { background: rgba(22,163,74,.1);   color: var(--green); }
    .badge-inactive { background: rgba(148,163,184,.15); color: var(--gray-400); }
    .badge-alta     { background: rgba(220,38,38,.1);   color: var(--red); }
    .badge-media    { background: rgba(217,119,6,.1);   color: var(--yellow); }
    .badge-baixa    { background: rgba(22,163,74,.1);   color: var(--green); }
    .badge-tipo     { background: rgba(37,99,196,.1);   color: var(--blue-400); }
    .notice-region  { font-size: .82rem; color: var(--gray-600); display: flex; align-items: center; gap: 5px; }
    .notice-msg     { font-size: .88rem; color: var(--gray-600); margin-top: 6px; }
    .notice-meta    { font-size: .75rem; color: var(--gray-400); margin-top: 8px; display: flex; gap: 12px; flex-wrap: wrap; }
    .notice-actions { display: flex; gap: 6px; flex-shrink: 0; }
    .empty-state { text-align: center; padding: 48px; color: var(--gray-400); }
    .empty-state i { font-size: 2.5rem; margin-bottom: 12px; }
    .empty-state p { font-size: .9rem; }

    /* ── Alertas de feedback ────────────────────────────────────── */
    .alert { padding: 12px 16px; border-radius: var(--radius-sm); font-size: .9rem; font-weight: 500; margin-bottom: 20px; display: flex; align-items: center; gap: 8px; }
    .alert-success { background: rgba(22,163,74,.1);  color: var(--green); border: 1px solid rgba(22,163,74,.2); }
    .alert-error   { background: rgba(220,38,38,.1);  color: var(--red);   border: 1px solid rgba(220,38,38,.2); }

    /* ── Páginas de autenticação (setup e login) ────────────────── */
    .auth-page { min-height: 100vh; display: flex; align-items: center; justify-content: center; background: linear-gradient(135deg, var(--blue-900), var(--blue-700)); }
    .auth-card { background: var(--white); border-radius: 20px; padding: 40px; width: 100%; max-width: 420px; box-shadow: 0 20px 60px rgba(0,0,0,.3); }
    .auth-logo { display: flex; align-items: center; gap: 10px; font-size: 1.3rem; font-weight: 900; margin-bottom: 28px; }
    .auth-logo .icon { width: 44px; height: 44px; background: linear-gradient(135deg,var(--blue-400),var(--orange)); border-radius: 12px; display: grid; place-items: center; font-size: 1.3rem; }
    .auth-logo span { color: var(--orange); }
    .auth-card h2 { font-size: 1.2rem; font-weight: 800; margin-bottom: 6px; }
    .auth-card p  { font-size: .88rem; color: var(--gray-600); margin-bottom: 24px; }
    .form-group-auth { margin-bottom: 16px; }
    .form-group-auth label { display: block; font-size: .82rem; font-weight: 600; color: var(--gray-600); margin-bottom: 6px; }
    .form-group-auth input { width: 100%; padding: 12px 14px; border: 2px solid var(--gray-200); border-radius: var(--radius-sm); font-family: inherit; font-size: .92rem; outline: none; transition: var(--transition); }
    .form-group-auth input:focus { border-color: var(--blue-400); box-shadow: 0 0 0 3px rgba(37,99,196,.1); }

    /* ── Preview da resposta da IA ──────────────────────────────── */
    .ia-preview { background: linear-gradient(135deg, var(--blue-800), var(--blue-900)); border-radius: var(--radius); padding: 20px; color: #fff; margin-top: 20px; }
    .ia-preview h4 { font-size: .85rem; color: rgba(255,255,255,.5); text-transform: uppercase; letter-spacing: .06em; margin-bottom: 12px; }
    .ia-bubble { background: rgba(255,255,255,.08); border-radius: 12px; padding: 14px 16px; font-size: .88rem; line-height: 1.6; color: rgba(255,255,255,.9); border-bottom-left-radius: 2px; }

    /* ── Responsivo ─────────────────────────────────────────────── */
    @media (max-width: 768px) {
      .layout { grid-template-columns: 1fr; }
      .sidebar { display: none; }
      .stats { grid-template-columns: 1fr 1fr; }
      .form-grid { grid-template-columns: 1fr; }
      .form-group.full { grid-column: span 1; }
    }
  </style>
</head>
<body>

<?php if ($isSetup): ?>
<!-- ═══════════════════════════════════════════════════════════════════
     VIEW: SETUP INICIAL
     Exibida apenas na primeira execução, quando não há senha definida.
═══════════════════════════════════════════════════════════════════ -->
<div class="auth-page">
  <div class="auth-card">
    <div class="auth-logo">
      <div class="icon">∞</div>
      Infinity<span>Web</span>
    </div>
    <h2>Configuração inicial</h2>
    <p>Crie uma senha de administrador para acessar o painel.</p>

    <?php if ($message): ?>
      <div class="alert alert-<?= $msgType === 'error' ? 'error' : 'success' ?>">
        <i class="fas fa-<?= $msgType === 'error' ? 'exclamation-circle' : 'check-circle' ?>"></i>
        <?= e($message) ?>
      </div>
    <?php endif; ?>

    <form method="POST" action="admin.php?action=setup">
      <div class="form-group-auth">
        <label for="setup-pwd">Nova senha (mín. 8 caracteres)</label>
        <input type="password" id="setup-pwd" name="password" required minlength="8" placeholder="••••••••" autofocus/>
      </div>
      <div class="form-group-auth">
        <label for="setup-pwd2">Confirmar senha</label>
        <input type="password" id="setup-pwd2" name="password2" required minlength="8" placeholder="••••••••"/>
      </div>
      <button type="submit" class="btn btn-orange btn-full">
        <i class="fas fa-shield-alt"></i> Criar senha e entrar
      </button>
    </form>
  </div>
</div>

<?php elseif (!isLoggedIn()): ?>
<!-- ═══════════════════════════════════════════════════════════════════
     VIEW: LOGIN
     Formulário de autenticação com proteção CSRF e rate limiting.
═══════════════════════════════════════════════════════════════════ -->
<div class="auth-page">
  <div class="auth-card">
    <div class="auth-logo">
      <div class="icon">∞</div>
      Infinity<span>Web</span>
    </div>
    <h2>Painel Administrativo</h2>
    <p>Acesso restrito à equipe Infinity Web.</p>

    <?php if ($message): ?>
      <div class="alert alert-<?= $msgType === 'error' ? 'error' : 'success' ?>">
        <i class="fas fa-<?= $msgType === 'error' ? 'exclamation-circle' : 'check-circle' ?>"></i>
        <?= e($message) ?>
      </div>
    <?php endif; ?>

    <form method="POST" action="admin.php?action=login">
      <!-- Token CSRF — gerado em helpers.php → csrfToken() -->
      <input type="hidden" name="csrf" value="<?= e(csrfToken()) ?>"/>
      <div class="form-group-auth">
        <label for="login-pwd">Senha de administrador</label>
        <input type="password" id="login-pwd" name="password" required placeholder="••••••••" autofocus/>
      </div>
      <button type="submit" class="btn btn-primary btn-full">
        <i class="fas fa-sign-in-alt"></i> Entrar
      </button>
    </form>
  </div>
</div>

<?php else: ?>
<!-- ═══════════════════════════════════════════════════════════════════
     VIEW: PAINEL ADMIN (usuário autenticado)
═══════════════════════════════════════════════════════════════════ -->

<!-- Topbar do painel -->
<div class="topbar">
  <div class="topbar-brand">
    <div class="icon">∞</div>
    Infinity<span>Web</span>
    <span style="color:rgba(255,255,255,.3);font-weight:400;font-size:.85rem">/ Admin</span>
  </div>
  <div class="topbar-right">
    <a href="index.html" target="_blank" rel="noopener noreferrer">
      <i class="fas fa-external-link-alt"></i> Ver site
    </a>
    <a href="admin.php?action=logout">
      <i class="fas fa-sign-out-alt"></i> Sair
    </a>
  </div>
</div>

<div class="layout">

  <!-- Sidebar de navegação -->
  <nav class="sidebar" aria-label="Menu administrativo">
    <div class="sidebar-label">Menu</div>
    <a href="admin.php?action=dashboard"
       class="<?= in_array($action, ['dashboard','create']) ? 'active' : '' ?>">
      <i class="fas fa-bell"></i> Avisos &amp; Alertas
    </a>
    <a href="admin.php?action=settings"
       class="<?= $action === 'settings' ? 'active' : '' ?>">
      <i class="fas fa-cog"></i> Configurações
    </a>
    <div class="sidebar-footer">
      <div class="label">IA conectada</div>
      <div class="status">
        <span class="dot-online"></span> Groq llama3-8b
      </div>
    </div>
  </nav>

  <!-- Conteúdo principal -->
  <main class="main">

    <?php if ($message): ?>
      <div class="alert alert-<?= $msgType === 'error' ? 'error' : 'success' ?>">
        <i class="fas fa-<?= $msgType === 'error' ? 'exclamation-circle' : 'check-circle' ?>"></i>
        <?= e($message) ?>
      </div>
    <?php endif; ?>

    <!-- ─── DASHBOARD / AVISOS ─── -->
    <?php if (in_array($action, ['dashboard', 'create'])): ?>

      <div class="page-header">
        <h1>Avisos &amp; Alertas</h1>
        <p>Crie avisos de instabilidade, manutenção ou quedas. A IA informará os clientes automaticamente no chat.</p>
      </div>

      <!-- Cards de estatísticas -->
      <div class="stats">
        <div class="stat-card">
          <div class="stat-icon si-total"><i class="fas fa-list"></i></div>
          <div class="stat-info">
            <div class="num"><?= count($notices) ?></div>
            <div class="lbl">Total de avisos</div>
          </div>
        </div>
        <div class="stat-card">
          <div class="stat-icon si-active"><i class="fas fa-exclamation-circle"></i></div>
          <div class="stat-info">
            <div class="num" style="color:var(--red)"><?= count($ativos) ?></div>
            <div class="lbl">Avisos ativos</div>
          </div>
        </div>
        <div class="stat-card">
          <div class="stat-icon si-ok"><i class="fas fa-check-circle"></i></div>
          <div class="stat-info">
            <div class="num" style="color:var(--green)"><?= count($notices) - count($ativos) ?></div>
            <div class="lbl">Desativados</div>
          </div>
        </div>
        <div class="stat-card">
          <div class="stat-icon si-exp"><i class="fas fa-clock"></i></div>
          <div class="stat-info">
            <div class="num" style="color:var(--yellow)"><?= count($expirados) ?></div>
            <div class="lbl">Expirados</div>
          </div>
        </div>
      </div>

      <!-- Formulário de criação de aviso -->
      <div class="card">
        <div class="card-header">
          <h3><i class="fas fa-plus-circle" style="color:var(--orange)"></i> &nbsp;Novo Aviso</h3>
        </div>
        <div class="card-body">
          <!-- handleCreateNotice() em includes/notices.php processa este POST -->
          <form method="POST" action="admin.php?action=create">
            <input type="hidden" name="csrf" value="<?= e(csrfToken()) ?>"/>
            <div class="form-grid">
              <div class="form-group">
                <label for="titulo">Título do aviso</label>
                <input type="text" id="titulo" name="titulo" placeholder="Ex: Instabilidade no sinal" required maxlength="120"/>
              </div>
              <div class="form-group">
                <label for="regiao">Região afetada</label>
                <select id="regiao" name="regiao">
                  <?php foreach ($regioes as $r): ?>
                    <option value="<?= e($r) ?>"><?= e($r) ?></option>
                  <?php endforeach; ?>
                </select>
              </div>
              <div class="form-group">
                <label for="tipo">Tipo de ocorrência</label>
                <select id="tipo" name="tipo">
                  <?php foreach ($tipos as $k => $v): ?>
                    <option value="<?= e($k) ?>"><?= e($v) ?></option>
                  <?php endforeach; ?>
                </select>
              </div>
              <div class="form-group">
                <label for="prioridade">Prioridade</label>
                <select id="prioridade" name="prioridade">
                  <option value="alta">🔴 Alta — impacto severo</option>
                  <option value="media" selected>🟡 Média — impacto parcial</option>
                  <option value="baixa">🟢 Baixa — impacto mínimo</option>
                </select>
              </div>
              <div class="form-group full">
                <label for="mensagem">Mensagem para a IA (o que informar aos clientes)</label>
                <textarea id="mensagem" name="mensagem"
                  placeholder="Ex: Estamos com instabilidade de sinal em Jordanesia. Nossa equipe técnica está em campo. Previsão de normalização: 2 horas."
                  required maxlength="600"></textarea>
              </div>
              <div class="form-group">
                <label for="expira">Expira em (opcional)</label>
                <input type="datetime-local" id="expira" name="expira"/>
              </div>
              <div class="form-group" style="display:flex;align-items:flex-end;">
                <button type="submit" class="btn btn-orange" style="width:100%;justify-content:center;padding:12px;">
                  <i class="fas fa-broadcast-tower"></i> Publicar aviso
                </button>
              </div>
            </div>
          </form>

          <!-- Preview da resposta que a IA dará ao cliente -->
          <div class="ia-preview">
            <h4><i class="fas fa-robot"></i> &nbsp;Preview — como a IA vai responder</h4>
            <div class="ia-bubble">
              🔴 <strong>Atenção!</strong> Neste momento temos um aviso ativo em nossa rede.<br><br>
              Estamos cientes da ocorrência e nossa equipe técnica já está trabalhando para resolver o mais rápido possível.
              Se preferir, pode entrar em contato pelo WhatsApp <strong>(11) 96401-2136</strong>. Pedimos desculpas pelo transtorno! 🙏
            </div>
          </div>
        </div>
      </div>

      <!-- Lista de avisos cadastrados -->
      <div class="card">
        <div class="card-header">
          <h3><i class="fas fa-list" style="color:var(--blue-400)"></i> &nbsp;Avisos cadastrados</h3>
          <span style="font-size:.82rem;color:var(--gray-400)"><?= count($notices) ?> total</span>
        </div>
        <div class="card-body">
          <?php if (empty($notices)): ?>
            <div class="empty-state">
              <i class="fas fa-check-circle" style="color:var(--green)"></i>
              <p>Nenhum aviso cadastrado.<br>Tudo operando normalmente! ✅</p>
            </div>
          <?php else: ?>
            <div class="notice-list">
              <?php foreach (array_reverse($notices) as $n):
                $expired  = $n['expira_em'] && $n['expira_em'] < $now;
                $priClass = 'badge-' . ($n['prioridade'] ?? 'media');
              ?>
                <div class="notice-item <?= !$n['ativo'] ? 'inactive' : '' ?>">
                  <div>
                    <div class="notice-top">
                      <span class="notice-title"><?= e($n['titulo']) ?></span>
                      <span class="badge <?= $n['ativo'] && !$expired ? 'badge-active' : 'badge-inactive' ?>">
                        <?= $n['ativo'] && !$expired ? '● Ativo' : ($expired ? '⏱ Expirado' : '○ Inativo') ?>
                      </span>
                      <span class="badge <?= $priClass ?>">
                        <?= e($prioridades[$n['prioridade'] ?? 'media'] ?? 'Média') ?>
                      </span>
                      <span class="badge badge-tipo">
                        <?= e($tipos[$n['tipo']] ?? $n['tipo']) ?>
                      </span>
                    </div>
                    <div class="notice-region">
                      <i class="fas fa-map-marker-alt" style="color:var(--orange)"></i>
                      <?= e($n['regiao']) ?>
                    </div>
                    <div class="notice-msg"><?= e($n['mensagem']) ?></div>
                    <div class="notice-meta">
                      <span><i class="fas fa-clock"></i> Criado: <?= e($n['criado_em']) ?></span>
                      <?php if ($n['expira_em']): ?>
                        <span><i class="fas fa-hourglass-end"></i> Expira: <?= e($n['expira_em']) ?></span>
                      <?php endif; ?>
                    </div>
                  </div>
                  <div class="notice-actions">
                    <!-- handleToggleNotice() em includes/notices.php -->
                    <a href="admin.php?action=toggle&id=<?= urlencode($n['id']) ?>"
                       class="btn btn-sm <?= $n['ativo'] ? 'btn-ghost' : 'btn-primary' ?>">
                      <i class="fas fa-<?= $n['ativo'] ? 'pause' : 'play' ?>"></i>
                      <?= $n['ativo'] ? 'Pausar' : 'Ativar' ?>
                    </a>
                    <!-- handleDeleteNotice() em includes/notices.php -->
                    <a href="admin.php?action=delete&id=<?= urlencode($n['id']) ?>"
                       class="btn btn-sm btn-danger"
                       onclick="return confirm('Confirma exclusão deste aviso?')">
                      <i class="fas fa-trash"></i>
                    </a>
                  </div>
                </div>
              <?php endforeach; ?>
            </div>
          <?php endif; ?>
        </div>
      </div>

    <!-- ─── CONFIGURAÇÕES ─── -->
    <?php elseif ($action === 'settings'): ?>

      <div class="page-header">
        <h1>Configurações</h1>
        <p>Altere a senha do painel administrativo.</p>
      </div>

      <div class="card" style="max-width:480px">
        <div class="card-header">
          <h3><i class="fas fa-key" style="color:var(--orange)"></i> &nbsp;Alterar senha</h3>
        </div>
        <div class="card-body">
          <form method="POST" action="admin.php?action=change-password">
            <input type="hidden" name="csrf" value="<?= e(csrfToken()) ?>"/>
            <div class="form-group" style="margin-bottom:14px">
              <label for="pwd-atual">Senha atual</label>
              <input type="password" id="pwd-atual" name="atual" required/>
            </div>
            <div class="form-group" style="margin-bottom:14px">
              <label for="pwd-nova">Nova senha (mín. 8 caracteres)</label>
              <input type="password" id="pwd-nova" name="nova" required minlength="8"/>
            </div>
            <div class="form-group" style="margin-bottom:20px">
              <label for="pwd-nova2">Confirmar nova senha</label>
              <input type="password" id="pwd-nova2" name="nova2" required minlength="8"/>
            </div>
            <button type="submit" class="btn btn-primary">
              <i class="fas fa-save"></i> Salvar senha
            </button>
          </form>
        </div>
      </div>

    <?php endif; ?>

  </main>
</div>

<?php endif; ?>

</body>
</html>
