/**
 * @file netlify/functions/admin-api.js
 * @description API do painel administrativo — lê e salva site-config.json via GitHub API.
 *
 * Variáveis de ambiente necessárias (Netlify → Environment variables):
 *   ADMIN_PASSWORD   — senha do painel admin
 *   GITHUB_TOKEN     — Personal Access Token com permissão "Contents: Write"
 *   GITHUB_REPO      — repositório no formato "usuario/repo" (ex: Norts023/infinityweb)
 *   GITHUB_BRANCH    — branch de produção (padrão: main)
 *
 * Endpoints:
 *   POST /api/admin  { action: "read", password }          → retorna config + sha
 *   POST /api/admin  { action: "save", password, config, sha } → salva via GitHub API
 */

const GITHUB_API  = 'https://api.github.com';
const CONFIG_PATH = 'data/site-config.json';

export default async (request, context) => {
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
  const GITHUB_TOKEN   = process.env.GITHUB_TOKEN;
  const GITHUB_REPO    = process.env.GITHUB_REPO   || 'Norts023/infinityweb';
  const GITHUB_BRANCH  = process.env.GITHUB_BRANCH || 'main';

  const headers = { 'Content-Type': 'application/json' };

  /* Apenas POST */
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405, headers });
  }

  /* Validação de configuração */
  if (!ADMIN_PASSWORD) {
    return new Response(
      JSON.stringify({ error: 'Painel não configurado. Adicione ADMIN_PASSWORD nas env vars do Netlify.' }),
      { status: 503, headers }
    );
  }

  /* Leitura do body */
  let body;
  try { body = await request.json(); }
  catch {
    return new Response(JSON.stringify({ error: 'Requisição inválida.' }), { status: 400, headers });
  }

  /* Autenticação — delay anti brute-force */
  if (body.password !== ADMIN_PASSWORD) {
    await new Promise(r => setTimeout(r, 800));
    return new Response(JSON.stringify({ error: 'Senha incorreta.' }), { status: 401, headers });
  }

  const ghHeaders = {
    'Authorization': `Bearer ${GITHUB_TOKEN}`,
    'Accept':        'application/vnd.github.v3+json',
    'Content-Type':  'application/json',
    'User-Agent':    'InfinityWeb-Admin/1.0',
  };

  /* ── READ: lê site-config.json do GitHub ──────────────────────────── */
  if (body.action === 'read') {
    try {
      const res = await fetch(
        `${GITHUB_API}/repos/${GITHUB_REPO}/contents/${CONFIG_PATH}?ref=${GITHUB_BRANCH}`,
        { headers: ghHeaders }
      );

      if (!res.ok) {
        throw new Error(`Arquivo não encontrado no repositório (HTTP ${res.status}).`);
      }

      const file   = await res.json();
      const config = JSON.parse(Buffer.from(file.content, 'base64').toString('utf-8'));

      return new Response(JSON.stringify({ config, sha: file.sha }), { headers });
    } catch (e) {
      console.error('[admin-api] read error:', e.message);
      return new Response(JSON.stringify({ error: e.message }), { status: 500, headers });
    }
  }

  /* ── SAVE: atualiza site-config.json no GitHub ─────────────────────── */
  if (body.action === 'save') {
    const { config, sha } = body;

    if (!config || !sha) {
      return new Response(JSON.stringify({ error: 'Dados incompletos (config ou sha ausente).' }), { status: 400, headers });
    }

    try {
      const content = Buffer.from(JSON.stringify(config, null, 2)).toString('base64');
      const timestamp = new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' });

      const res = await fetch(
        `${GITHUB_API}/repos/${GITHUB_REPO}/contents/${CONFIG_PATH}`,
        {
          method:  'PUT',
          headers: ghHeaders,
          body:    JSON.stringify({
            message: `admin: atualiza configurações do site (${timestamp})`,
            content,
            sha,
            branch: GITHUB_BRANCH,
          }),
        }
      );

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.message || `GitHub API retornou ${res.status}`);
      }

      const result = await res.json();
      const newSha = result?.content?.sha;

      return new Response(JSON.stringify({ ok: true, sha: newSha }), { headers });
    } catch (e) {
      console.error('[admin-api] save error:', e.message);
      return new Response(JSON.stringify({ error: e.message }), { status: 500, headers });
    }
  }

  return new Response(JSON.stringify({ error: 'Ação desconhecida.' }), { status: 400, headers });
};

export const config = { path: '/api/admin' };
