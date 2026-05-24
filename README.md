# ∞ Infinity Web — Site Institucional com Chat IA

![HTML](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![CSS](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![Netlify](https://img.shields.io/badge/Netlify-00C7B7?style=for-the-badge&logo=netlify&logoColor=white)
![Groq](https://img.shields.io/badge/Groq_AI-F55036?style=for-the-badge&logo=groq&logoColor=white)

> Redesign moderno e responsivo do site de um provedor de internet fibra óptica, com chat de atendimento via IA (Groq / LLaMA 3) e painel administrativo para a equipe de suporte.

---

## 🌐 Demo ao vivo

**👉 [Ver site funcionando](https://SEU-LINK.netlify.app)**
> *(atualize este link após o deploy no Netlify)*

---

## ✨ Funcionalidades

- **Design moderno e responsivo** — hero animado, cards de planos, seção de cobertura, depoimentos e rodapé completo
- **Chat IA com Groq** — atendimento 24h via LLaMA 3 (llama3-8b-8192), respondendo sobre planos, cobertura, suporte e boletos
- **Painel Admin** — equipe de suporte publica avisos (instabilidade, manutenção, queda de sinal) e a IA informa os clientes automaticamente
- **Segurança** — chave da API nunca exposta no frontend; proxy serverless via Netlify Functions; rate limiting e sanitização XSS (DOMPurify)
- **Totalmente estático** — deploy em qualquer CDN, sem banco de dados

---

## 🛠️ Tecnologias

| Camada | Tecnologia |
|--------|-----------|
| Frontend | HTML5, CSS3 (variáveis, animations, grid), JavaScript vanilla |
| Chat IA | [Groq API](https://groq.com) — LLaMA 3 8B (llama3-8b-8192) |
| Proxy seguro | Netlify Edge Function (Node.js) |
| Fontes & ícones | Google Fonts (Inter), Font Awesome 6 |
| Sanitização | DOMPurify 3 |
| Deploy | Netlify (CI/CD automático via GitHub) |

---

## 🏗️ Estrutura do projeto

```
Projeto Infinity WEB/
│
├── index.html                        # Landing page (HTML puro, sem CSS/JS inline)
├── admin.php                         # Painel admin — ponto de entrada PHP
├── groq-proxy.php                    # Proxy da API Groq (hospedagem PHP)
├── groq-proxy.example.php            # Template sem chave (versionável)
├── netlify.toml                      # Roteamento Netlify
│
├── assets/
│   ├── css/
│   │   ├── variables.css             # Design tokens: cores, sombras, transições
│   │   ├── components.css            # Botões, badges, container, tipografia
│   │   ├── layout.css                # Topbar, navegação sticky, footer
│   │   ├── sections.css              # Cada seção da landing page
│   │   ├── chat.css                  # Widget de chat com IA
│   │   └── responsive.css            # Media queries (importar por último)
│   └── js/
│       ├── navigation.js             # Menu hamburger, smooth scroll, scroll-top
│       ├── animations.js             # Counter de velocidade (Intersection Observer)
│       ├── plans.js                  # Função setTab() — alternância de abas
│       ├── form.js                   # Função submitForm() — feedback do formulário
│       └── chat.js                   # Chat IA: DOMPurify + rate limit + proxy Groq
│
├── includes/                         # Módulos PHP do painel admin
│   ├── config.php                    # Constantes (caminhos, limites de segurança)
│   ├── helpers.php                   # e(), readJson(), writeJson(), CSRF
│   ├── auth.php                      # Login, sessão, rate limiting de tentativas
│   └── notices.php                   # CRUD de avisos, getNoticesMeta()
│
├── netlify/
│   └── functions/
│       └── groq-proxy.js             # Proxy Node.js — chave via env var GROQ_API_KEY
│
└── data/                             # Dados JSON (bloqueados via .htaccess)
    ├── .htaccess                     # Nega acesso HTTP direto à pasta
    ├── notices.json                  # Avisos ativos da equipe de suporte
    └── admin-config.json             # Hash bcrypt da senha do admin
```

---

## 🚀 Deploy no Netlify (5 min)

### 1. Fork ou clone este repositório

```bash
git clone https://github.com/Norts023/infinityweb.git
```

### 2. Crie conta gratuita no Netlify

Acesse [netlify.com](https://netlify.com) → **Sign up with GitHub**

### 3. Conecte o repositório

**Add new site** → **Import an existing project** → selecione este repo → **Deploy site**

### 4. Configure a variável de ambiente

No painel do Netlify:
```
Site configuration → Environment variables → Add variable

GROQ_API_KEY = gsk_sua_chave_aqui
```

Obtenha sua chave gratuita em [console.groq.com](https://console.groq.com)

### 5. Redeploy

**Deploys** → **Trigger deploy** → pronto! 🎉

---

## 🔒 Segurança implementada

| Risco | Mitigação | Arquivo |
|---|---|---|
| XSS em respostas da IA (CWE-79) | DOMPurify sanitiza todo HTML antes de `innerHTML` | `chat.js` |
| XSS em output PHP (CWE-79) | `e()` escapa todo dado dinâmico no HTML | `includes/helpers.php` |
| Exposição da chave de API (CWE-312) | Chave fica apenas no servidor (proxy ou env var) | `groq-proxy.php` / Netlify |
| CSRF em formulários (CWE-352) | Token `random_bytes(32)` + `hash_equals` | `includes/helpers.php` |
| Brute force de login | Rate limiting por IP: 5 tentativas / 5 min + `usleep` | `includes/auth.php` |
| Session fixation | `session_regenerate_id(true)` após login bem-sucedido | `admin.php` |
| Acesso a arquivos JSON | `.htaccess` bloqueia qualquer requisição HTTP a `/data` | `data/.htaccess` |
| Open Redirect (CWE-1022) | Hook DOMPurify força `rel="noopener noreferrer"` em links | `chat.js` |
| Prompt injection | System prompt com regras explícitas de escopo e rejeição | `groq-proxy.php` |

---

## 📋 Planos exibidos no site

| Plano | Velocidade | Preço |
|-------|-----------|-------|
| Residencial Básico | 300 Mega | R$ 99,99/mês |
| Residencial Plus | 400 Mega | R$ 119,99/mês |
| Residencial Ultra | 650 Mega | R$ 159,99/mês |

---

## 📸 Screenshots

> *Adicione prints do site aqui após o deploy*

---

## 👤 Autor

Desenvolvido por **Marcos** · [@Norts023](https://github.com/Norts023)

---

## 📄 Licença

Este projeto é um estudo/portfólio. O conteúdo pertence à **Infinity Web** — Cajamar-SP.
