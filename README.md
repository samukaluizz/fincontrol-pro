# FinControl Pro — Dashboard Financeiro Empresarial

## Deploy no Railway (gratuito)

### Passo 1 — Crie uma conta no GitHub
Acesse https://github.com e crie uma conta gratuita (se ainda não tiver).

### Passo 2 — Crie um repositório
1. No GitHub, clique em **"New repository"**
2. Nome: `fincontrol-pro`
3. Deixe **Public** ou **Private** (os dois funcionam)
4. Clique em **"Create repository"**

### Passo 3 — Faça upload dos arquivos
Na página do repositório recém-criado:
1. Clique em **"uploading an existing file"**
2. Arraste TODOS estes arquivos de uma vez:
   - `app.py`
   - `requirements.txt`
   - `Procfile`
   - `runtime.txt`
   - `.gitignore`
3. Clique em **"Commit changes"**

### Passo 4 — Deploy no Railway
1. Acesse https://railway.app e clique em **"Login with GitHub"**
2. Clique em **"New Project"**
3. Selecione **"Deploy from GitHub repo"**
4. Escolha o repositório `fincontrol-pro`
5. Clique em **"Deploy Now"**
6. Aguarde 1-2 minutos o deploy concluir

### Passo 5 — Gerar URL pública
1. No painel do Railway, clique no seu serviço
2. Vá em **Settings → Networking**
3. Clique em **"Generate Domain"**
4. Sua URL será algo como: `fincontrol-pro.up.railway.app`

## Contas de acesso

| Perfil       | E-mail                        | Senha     |
|--------------|-------------------------------|-----------|
| ⭐ Super Admin | superadmin@fincontrol.com    | super123  |
| 🏢 Admin      | admin@techcorp.com           | tech123   |
| 🏢 Admin      | admin@vendamais.com          | venda123  |
| 👤 Usuário    | joao@techcorp.com            | joao123   |
| 👤 Usuário    | maria@vendamais.com          | maria123  |

## Rodar localmente

```bash
pip install flask gunicorn
python app.py
# Acesse: http://localhost:5000
```
