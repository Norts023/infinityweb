# Infinity Web — Contexto do Projeto para IA

Provedor de internet fibra óptica em Cajamar-SP (Jordanesia).

## Estrutura de Arquivos

```
/
├── index.html                        # Landing page principal
├── admin.php                         # Painel administrativo (ponto de entrada)
├── groq-proxy.php                    # Proxy da API Groq (hospedagem PHP)
├── netlify.toml                      # Configuração de roteamento Netlify
│
├── assets/
│   ├── css/
│   │   ├── variables.css             # Design tokens globais (cores, sombras)
│   │   ├── components.css            # Botões, badges, utilitários
│   │   ├── layout.css                # Topbar, nav, footer
│   │   ├── sections.css              # Seções da landing page
│   │   ├── chat.css                  # Widget de chat com IA
│   │   └── responsive.css            # Media queries (importar por último)
│   └── js/
│       ├── navigation.js             # Hamburger, smooth scroll, scroll-top
│       ├── animations.js             # Counter de velocidade (hero)
│       ├── plans.js                  # Tabs de planos (setTab)
│       ├── form.js                   # Formulário de contato (submitForm)
│       └── chat.js                   # Widget de IA — DOMPurify + Groq
│
├── includes/                         # Módulos PHP do painel admin
│   ├── config.php                    # Constantes (caminhos, limites)
│   ├── helpers.php                   # e(), readJson(), writeJson(), CSRF
│   ├── auth.php                      # Login, sessão, rate limiting
│   └── notices.php                   # CRUD de avisos, getNoticesMeta()
│
├── netlify/
│   └── functions/
│       └── groq-proxy.js             # Proxy Node.js (Netlify Functions)
│
└── data/                             # Dados JSON (protegidos por .htaccess)
    ├── .htaccess                     # Bloqueia acesso web direto à pasta
    ├── notices.json                  # Avisos ativos criados pelo admin
    └── admin-config.json             # Hash bcrypt da senha do admin
```

## Comandos Úteis

- **Testar localmente (PHP):** `php -S localhost:8000`
- **Deploy Netlify:** push para main → build automático
- **Configurar chave Groq (PHP):** editar `groq-proxy.php` → `GROQ_API_KEY`
- **Configurar chave Groq (Netlify):** Dashboard → Environment variables → `GROQ_API_KEY`
