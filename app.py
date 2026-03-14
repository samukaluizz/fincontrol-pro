"""
Dashboard de Controle Financeiro Empresarial v2
Hierarquia: superadmin > admin (empresa) > user
"""

import sqlite3, hashlib, secrets, string, random, os
from functools import wraps
from flask import Flask, request, jsonify, session

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
DB_PATH = "finance.db"

# ── DB ──────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

def gen_password(length=10):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=length))

def init_db():
    conn = get_db(); c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL, plain_password TEXT,
        role TEXT DEFAULT 'user',
        company TEXT, company_id INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now','localtime'))
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL, company_id INTEGER NOT NULL DEFAULT 0,
        type TEXT NOT NULL, category TEXT NOT NULL,
        description TEXT, amount REAL NOT NULL, date TEXT NOT NULL,
        status TEXT DEFAULT 'concluido',
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS budgets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL, category TEXT NOT NULL,
        limit_amount REAL NOT NULL, month TEXT NOT NULL
    )""")

    # Superadmin (company_id=0 = sem empresa / acesso total)
    c.execute("INSERT OR IGNORE INTO users (name,email,password,plain_password,role,company,company_id) VALUES (?,?,?,?,?,?,?)",
              ("Super Admin","superadmin@fincontrol.com", hash_pw("super123"), "super123", "superadmin","FinControl",0))

    # Demo: empresa "TechCorp" com admin + user
    c.execute("INSERT OR IGNORE INTO users (name,email,password,plain_password,role,company,company_id) VALUES (?,?,?,?,?,?,?)",
              ("Admin TechCorp","admin@techcorp.com", hash_pw("tech123"), "tech123", "admin","TechCorp",1))
    c.execute("INSERT OR IGNORE INTO users (name,email,password,plain_password,role,company,company_id) VALUES (?,?,?,?,?,?,?)",
              ("João Silva","joao@techcorp.com", hash_pw("joao123"), "joao123", "user","TechCorp",1))

    # Demo: empresa "VendaMais" com admin + user
    c.execute("INSERT OR IGNORE INTO users (name,email,password,plain_password,role,company,company_id) VALUES (?,?,?,?,?,?,?)",
              ("Admin VendaMais","admin@vendamais.com", hash_pw("venda123"), "venda123", "admin","VendaMais",2))
    c.execute("INSERT OR IGNORE INTO users (name,email,password,plain_password,role,company,company_id) VALUES (?,?,?,?,?,?,?)",
              ("Maria Souza","maria@vendamais.com", hash_pw("maria123"), "maria123", "user","VendaMais",2))

    # Seed transactions por empresa
    for uid_email, cid, data_list in [
        ("admin@techcorp.com", 1, [
            ("receita","Vendas","Venda de licenças",22000,"2025-03-02"),
            ("receita","Serviços","Consultoria Q1",9500,"2025-03-08"),
            ("despesa","Salários","Folha março",11000,"2025-03-05"),
            ("despesa","Aluguel","Escritório SP",4200,"2025-03-01"),
            ("despesa","Marketing","LinkedIn Ads",1800,"2025-03-10"),
            ("receita","Vendas","Renovação contratos",15000,"2025-02-15"),
            ("despesa","Tecnologia","AWS fevereiro",2300,"2025-02-01"),
        ]),
        ("admin@vendamais.com", 2, [
            ("receita","Vendas","E-commerce março",31000,"2025-03-03"),
            ("receita","Vendas","Marketplace",8700,"2025-03-11"),
            ("despesa","Salários","Equipe comercial",13500,"2025-03-05"),
            ("despesa","Logística","Frete e entregas",3900,"2025-03-07"),
            ("despesa","Marketing","Meta Ads",5200,"2025-03-01"),
            ("receita","Serviços","Consultoria vendas",4000,"2025-02-20"),
            ("despesa","Aluguel","Galpão estoque",6000,"2025-02-01"),
        ]),
    ]:
        row = c.execute("SELECT id FROM users WHERE email=?", (uid_email,)).fetchone()
        if row:
            uid = row[0]
            c.execute("SELECT COUNT(*) FROM transactions WHERE user_id=?", (uid,))
            if c.fetchone()[0] == 0:
                for tp,cat,desc,amt,dt in data_list:
                    c.execute("INSERT INTO transactions (user_id,company_id,type,category,description,amount,date) VALUES (?,?,?,?,?,?,?)",
                              (uid,cid,tp,cat,desc,amt,dt))
    conn.commit(); conn.close()

# ── AUTH DECORATORS ──────────────────────────────
def login_required(f):
    @wraps(f)
    def d(*a,**k):
        if "user_id" not in session: return jsonify({"error":"Não autorizado"}),401
        return f(*a,**k)
    return d

def admin_or_super(f):
    @wraps(f)
    def d(*a,**k):
        if session.get("role") not in ("admin","superadmin"): return jsonify({"error":"Acesso negado"}),403
        return f(*a,**k)
    return d

# ── HELPERS ─────────────────────────────────────
def company_filter():
    """Returns (where_clause, params) based on current session role"""
    role = session.get("role")
    cid  = session.get("company_id", 0)
    if role == "superadmin":
        return "", []
    elif role == "admin":
        return "WHERE company_id=?", [cid]
    else:  # user
        return "WHERE user_id=?", [session["user_id"]]

# ── AUTH ROUTES ──────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    d = request.json
    conn = get_db()
    u = conn.execute("SELECT * FROM users WHERE email=? AND password=?",
                     (d["email"], hash_pw(d["password"]))).fetchone()
    conn.close()
    if u:
        session.update({"user_id":u["id"],"name":u["name"],"role":u["role"],
                        "company":u["company"],"company_id":u["company_id"]})
        return jsonify({"ok":True,"name":u["name"],"role":u["role"],"company":u["company"]})
    return jsonify({"error":"Credenciais inválidas"}),401

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear(); return jsonify({"ok":True})

@app.route("/api/me")
def me():
    if "user_id" not in session: return jsonify({"logged":False})
    return jsonify({"logged":True,"name":session["name"],"role":session["role"],
                    "company":session.get("company",""),"company_id":session.get("company_id",0)})

# ── USERS ────────────────────────────────────────
@app.route("/api/users", methods=["GET"])
@login_required
@admin_or_super
def list_users():
    conn = get_db()
    role = session["role"]; cid = session.get("company_id",0)
    if role == "superadmin":
        # Super vê todos, agrupados
        rows = conn.execute("""
            SELECT id,name,email,role,company,company_id,plain_password,created_at
            FROM users ORDER BY company_id, role DESC, name
        """).fetchall()
    else:
        # Admin vê apenas sua empresa, exceto outros admins de outras empresas
        rows = conn.execute("""
            SELECT id,name,email,role,company,company_id,plain_password,created_at
            FROM users WHERE company_id=? ORDER BY role DESC, name
        """, (cid,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/users", methods=["POST"])
@login_required
@admin_or_super
def create_user():
    d = request.json
    role = session["role"]; cid = session.get("company_id",0)
    new_role = d.get("role","user")

    # Admin de empresa só pode criar 'user' na própria empresa
    if role == "admin":
        if new_role not in ("user",): new_role = "user"
        company = session.get("company","")
        company_id = cid
    else:
        # superadmin pode criar qualquer coisa
        company = d.get("company","")
        company_id = int(d.get("company_id") or 0)
        # Se criar admin de empresa nova, gera company_id único
        if new_role == "admin" and not company_id:
            conn2 = get_db()
            max_cid = conn2.execute("SELECT COALESCE(MAX(company_id),0) FROM users").fetchone()[0]
            conn2.close()
            company_id = max_cid + 1

    if not all([d.get("name"), d.get("email")]):
        return jsonify({"error":"Campos obrigatórios ausentes"}),400

    # Senha: usa a fornecida ou gera automaticamente
    plain = d.get("password") or gen_password()

    conn = get_db()
    try:
        conn.execute("""INSERT INTO users (name,email,password,plain_password,role,company,company_id)
                        VALUES (?,?,?,?,?,?,?)""",
                     (d["name"],d["email"],hash_pw(plain),plain,new_role,company,company_id))
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error":"E-mail já cadastrado"}),409
    finally:
        conn.close()
    return jsonify({"ok":True,"plain_password":plain,"email":d["email"]})

@app.route("/api/users/<int:uid>", methods=["DELETE"])
@login_required
@admin_or_super
def delete_user(uid):
    if uid == session["user_id"]: return jsonify({"error":"Não pode excluir a si mesmo"}),400
    conn = get_db()
    target = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not target: return jsonify({"error":"Usuário não encontrado"}),404
    # Admin só pode deletar users da própria empresa
    if session["role"] == "admin" and target["company_id"] != session.get("company_id"):
        return jsonify({"error":"Sem permissão"}),403
    conn.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.commit(); conn.close()
    return jsonify({"ok":True})

@app.route("/api/users/<int:uid>/reset-password", methods=["POST"])
@login_required
@admin_or_super
def reset_password(uid):
    conn = get_db()
    target = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not target: return jsonify({"error":"Não encontrado"}),404
    if session["role"] == "admin" and target["company_id"] != session.get("company_id"):
        return jsonify({"error":"Sem permissão"}),403
    new_plain = gen_password()
    conn.execute("UPDATE users SET password=?, plain_password=? WHERE id=?",
                 (hash_pw(new_plain), new_plain, uid))
    conn.commit(); conn.close()
    return jsonify({"ok":True,"plain_password":new_plain,"email":target["email"]})

# ── TRANSACTIONS ─────────────────────────────────
@app.route("/api/transactions", methods=["GET"])
@login_required
def list_transactions():
    conn = get_db()
    role = session["role"]; cid = session.get("company_id",0); uid = session["user_id"]
    if role == "superadmin":
        rows = conn.execute("""SELECT t.*,u.name as user_name,u.company FROM transactions t
            JOIN users u ON t.user_id=u.id ORDER BY t.date DESC LIMIT 200""").fetchall()
    elif role == "admin":
        rows = conn.execute("""SELECT t.*,u.name as user_name,u.company FROM transactions t
            JOIN users u ON t.user_id=u.id WHERE t.company_id=?
            ORDER BY t.date DESC LIMIT 200""",(cid,)).fetchall()
    else:
        rows = conn.execute("""SELECT t.*,u.name as user_name,u.company FROM transactions t
            JOIN users u ON t.user_id=u.id WHERE t.user_id=?
            ORDER BY t.date DESC LIMIT 100""",(uid,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/transactions", methods=["POST"])
@login_required
def create_transaction():
    d = request.json; uid = session["user_id"]; cid = session.get("company_id",0)
    conn = get_db()
    conn.execute("""INSERT INTO transactions (user_id,company_id,type,category,description,amount,date,status)
                    VALUES (?,?,?,?,?,?,?,?)""",
                 (uid,cid,d["type"],d["category"],d.get("description",""),
                  float(d["amount"]),d["date"],d.get("status","concluido")))
    conn.commit(); conn.close()
    return jsonify({"ok":True})

@app.route("/api/transactions/<int:tid>", methods=["DELETE"])
@login_required
def delete_transaction(tid):
    uid = session["user_id"]; role = session["role"]; cid = session.get("company_id",0)
    conn = get_db()
    if role == "superadmin":
        conn.execute("DELETE FROM transactions WHERE id=?",(tid,))
    elif role == "admin":
        conn.execute("DELETE FROM transactions WHERE id=? AND company_id=?",(tid,cid))
    else:
        conn.execute("DELETE FROM transactions WHERE id=? AND user_id=?",(tid,uid))
    conn.commit(); conn.close()
    return jsonify({"ok":True})

# ── SUMMARY ──────────────────────────────────────
@app.route("/api/summary")
@login_required
def summary():
    conn = get_db()
    role = session["role"]; cid = session.get("company_id",0); uid = session["user_id"]

    def q(sql, params=[]): return conn.execute(sql, params).fetchone()[0]
    def qall(sql, params=[]): return [dict(r) for r in conn.execute(sql, params).fetchall()]

    if role == "superadmin":
        flt, p = "", []
    elif role == "admin":
        flt, p = "WHERE company_id=?", [cid]
    else:
        flt, p = "WHERE user_id=?", [uid]

    f2 = flt.replace("WHERE","AND") if flt else ""

    receitas = q(f"SELECT COALESCE(SUM(amount),0) FROM transactions {flt} {'AND' if flt else 'WHERE'} type='receita'".replace("  "," "), p)
    despesas = q(f"SELECT COALESCE(SUM(amount),0) FROM transactions {flt} {'AND' if flt else 'WHERE'} type='despesa'".replace("  "," "), p)
    total_tx = q(f"SELECT COUNT(*) FROM transactions {flt}", p)

    # easier approach
    if role == "superadmin":
        receitas = q("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE type='receita'")
        despesas = q("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE type='despesa'")
        total_tx = q("SELECT COUNT(*) FROM transactions")
        monthly  = qall("""SELECT strftime('%Y-%m',date) m,
            SUM(CASE WHEN type='receita' THEN amount ELSE 0 END) receitas,
            SUM(CASE WHEN type='despesa' THEN amount ELSE 0 END) despesas
            FROM transactions GROUP BY m ORDER BY m DESC LIMIT 6""")
        by_cat   = qall("""SELECT category,SUM(amount) total,type FROM transactions
            GROUP BY category,type ORDER BY total DESC LIMIT 12""")
        total_users    = q("SELECT COUNT(*) FROM users")
        total_empresas = q("SELECT COUNT(DISTINCT company_id) FROM users WHERE role='admin'")
    elif role == "admin":
        receitas = q("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE company_id=? AND type='receita'",[cid])
        despesas = q("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE company_id=? AND type='despesa'",[cid])
        total_tx = q("SELECT COUNT(*) FROM transactions WHERE company_id=?",[cid])
        monthly  = qall("""SELECT strftime('%Y-%m',date) m,
            SUM(CASE WHEN type='receita' THEN amount ELSE 0 END) receitas,
            SUM(CASE WHEN type='despesa' THEN amount ELSE 0 END) despesas
            FROM transactions WHERE company_id=? GROUP BY m ORDER BY m DESC LIMIT 6""",[cid])
        by_cat   = qall("""SELECT category,SUM(amount) total,type FROM transactions
            WHERE company_id=? GROUP BY category,type ORDER BY total DESC LIMIT 12""",[cid])
        total_users    = q("SELECT COUNT(*) FROM users WHERE company_id=?",[cid])
        total_empresas = 1
    else:
        receitas = q("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE user_id=? AND type='receita'",[uid])
        despesas = q("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE user_id=? AND type='despesa'",[uid])
        total_tx = q("SELECT COUNT(*) FROM transactions WHERE user_id=?",[uid])
        monthly  = qall("""SELECT strftime('%Y-%m',date) m,
            SUM(CASE WHEN type='receita' THEN amount ELSE 0 END) receitas,
            SUM(CASE WHEN type='despesa' THEN amount ELSE 0 END) despesas
            FROM transactions WHERE user_id=? GROUP BY m ORDER BY m DESC LIMIT 6""",[uid])
        by_cat   = qall("""SELECT category,SUM(amount) total,type FROM transactions
            WHERE user_id=? GROUP BY category,type ORDER BY total DESC LIMIT 12""",[uid])
        total_users    = 1
        total_empresas = 1

    conn.close()
    return jsonify({"receitas":receitas,"despesas":despesas,"saldo":receitas-despesas,
                    "total_transactions":total_tx,"monthly":list(reversed(monthly)),
                    "by_category":by_cat,"total_users":total_users,"total_empresas":total_empresas})

# ── COMPANIES (superadmin) ────────────────────────
@app.route("/api/companies")
@login_required
def list_companies():
    if session["role"] != "superadmin": return jsonify({"error":"Acesso negado"}),403
    conn = get_db()
    rows = conn.execute("""
        SELECT u.company, u.company_id,
               COUNT(DISTINCT u2.id) as total_users,
               (SELECT COUNT(*) FROM transactions t WHERE t.company_id=u.company_id) as total_tx
        FROM users u
        LEFT JOIN users u2 ON u2.company_id=u.company_id
        WHERE u.role='admin'
        GROUP BY u.company_id
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ── HTML ─────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>FinControl Pro</title>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Mono:wght@400;500&family=DM+Sans:ital,wght@0,300;0,400;0,500;1,400&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{--bg:#080b10;--s1:#0f1319;--s2:#161b24;--s3:#1c2230;--border:#222a36;
  --accent:#00d4aa;--purple:#7c6ef5;--red:#ff4d6d;--yellow:#ffbe0b;--blue:#3b9eff;
  --text:#e4e8f0;--muted:#64748b;--radius:14px;
  --font:'DM Sans',sans-serif;--display:'Syne',sans-serif;--mono:'DM Mono',monospace;}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--font);min-height:100vh}

/* ── LOGIN ── */
#login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh;
  background:radial-gradient(ellipse 60% 50% at 20% 60%,rgba(0,212,170,.1) 0,transparent 70%),
             radial-gradient(ellipse 50% 40% at 80% 20%,rgba(124,110,245,.1) 0,transparent 70%),var(--bg)}
.lcard{background:var(--s1);border:1px solid var(--border);border-radius:22px;padding:48px 42px;width:430px;
  box-shadow:0 40px 80px rgba(0,0,0,.6);animation:up .45s ease}
@keyframes up{from{opacity:0;transform:translateY(24px)}to{opacity:1;transform:translateY(0)}}
.logo{font-family:var(--display);font-size:26px;font-weight:800;
  background:linear-gradient(135deg,var(--accent),var(--purple));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:6px}
.logo-sub{color:var(--muted);font-size:13px;margin-bottom:36px}
.field{margin-bottom:18px}
.field label{display:block;font-size:11px;font-weight:500;color:var(--muted);
  text-transform:uppercase;letter-spacing:.08em;margin-bottom:7px}
input,select{width:100%;background:var(--s2);border:1px solid var(--border);border-radius:10px;
  padding:11px 15px;color:var(--text);font-family:var(--font);font-size:14px;outline:none;transition:border .2s}
input:focus,select:focus{border-color:var(--accent)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;padding:11px 22px;
  border-radius:9px;border:none;cursor:pointer;font-family:var(--display);font-weight:600;
  font-size:13px;transition:all .18s;white-space:nowrap}
.btn-p{background:var(--accent);color:#06100d;width:100%}
.btn-p:hover{background:#00bfa3;box-shadow:0 6px 20px rgba(0,212,170,.3);transform:translateY(-1px)}
.btn-r{background:rgba(255,77,109,.12);color:var(--red);border:1px solid rgba(255,77,109,.25)}
.btn-r:hover{background:rgba(255,77,109,.22)}
.btn-g{background:transparent;color:var(--text);border:1px solid var(--border)}
.btn-g:hover{background:var(--s2)}
.btn-b{background:rgba(59,158,255,.12);color:var(--blue);border:1px solid rgba(59,158,255,.25)}
.btn-b:hover{background:rgba(59,158,255,.22)}
.btn-sm{padding:6px 13px;font-size:11px;border-radius:7px}
.err{color:var(--red);font-size:12px;margin-top:10px;text-align:center;min-height:16px}

/* ── LAYOUT ── */
#app{display:none}
.sidebar{position:fixed;left:0;top:0;bottom:0;width:248px;background:var(--s1);
  border-right:1px solid var(--border);padding:26px 0;display:flex;flex-direction:column;z-index:100}
.sb-logo{padding:0 22px 26px;border-bottom:1px solid var(--border)}
.sb-logo .lt{font-family:var(--display);font-weight:800;font-size:20px;
  background:linear-gradient(135deg,var(--accent),var(--purple));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent}
.sb-logo .ls{font-size:11px;color:var(--muted);margin-top:2px}
.nav{flex:1;padding:18px 10px;display:flex;flex-direction:column;gap:3px}
.ni{display:flex;align-items:center;gap:11px;padding:9px 12px;border-radius:9px;
  cursor:pointer;color:var(--muted);font-size:13px;font-weight:500;transition:all .15s}
.ni:hover{background:var(--s2);color:var(--text)}
.ni.active{background:rgba(0,212,170,.1);color:var(--accent)}
.ni svg{flex-shrink:0;width:16px;height:16px}
.sb-footer{padding:14px 22px;border-top:1px solid var(--border)}
.sb-name{font-size:13px;font-weight:600}
.sb-role{font-size:11px;color:var(--muted);margin-top:2px}
/* role badge in sidebar */
.role-badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:10px;font-weight:600;margin-top:4px}
.rb-super{background:rgba(255,190,11,.15);color:var(--yellow)}
.rb-admin{background:rgba(0,212,170,.12);color:var(--accent)}
.rb-user {background:rgba(124,110,245,.12);color:var(--purple)}

.main{margin-left:248px;padding:30px;min-height:100vh}
.page{display:none}
.page.active{display:block;animation:fadein .25s ease}
@keyframes fadein{from{opacity:0}to{opacity:1}}
.ph{margin-bottom:26px;display:flex;justify-content:space-between;align-items:flex-start}
.pt{font-family:var(--display);font-size:24px;font-weight:700}
.ps{color:var(--muted);font-size:13px;margin-top:3px}

/* ── CARDS ── */
.cgrid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px}
.card{background:var(--s1);border:1px solid var(--border);border-radius:var(--radius);
  padding:20px;position:relative;overflow:hidden;transition:border-color .2s}
.card:hover{border-color:rgba(0,212,170,.4)}
.cl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;font-weight:500}
.cv{font-family:var(--mono);font-size:26px;font-weight:500;margin:7px 0 3px}
.cc{font-size:11px;color:var(--muted)}
.ci{position:absolute;right:16px;top:16px;font-size:28px;opacity:.12}

/* ── CHARTS ── */
.crow{display:grid;grid-template-columns:2fr 1fr;gap:14px;margin-bottom:24px}
.cc2{background:var(--s1);border:1px solid var(--border);border-radius:var(--radius);padding:22px}
.ct{font-family:var(--display);font-size:14px;font-weight:600;margin-bottom:18px}

/* ── TABLE ── */
.tcard{background:var(--s1);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;margin-bottom:16px}
.th2{padding:18px 22px;display:flex;align-items:center;justify-content:space-between;
  border-bottom:1px solid var(--border)}
.tt{font-family:var(--display);font-weight:600;font-size:14px}
table{width:100%;border-collapse:collapse}
th{padding:10px 22px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.08em;
  color:var(--muted);font-weight:500;background:var(--s2)}
td{padding:12px 22px;font-size:12px;border-bottom:1px solid var(--border)}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.015)}
.badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:10px;font-weight:600}
.b-receita{background:rgba(0,212,170,.12);color:var(--accent)}
.b-despesa{background:rgba(255,77,109,.12);color:var(--red)}
.b-concluido{background:rgba(0,212,170,.1);color:var(--accent)}
.b-pendente{background:rgba(255,190,11,.1);color:var(--yellow)}
.b-super{background:rgba(255,190,11,.15);color:var(--yellow)}
.b-admin{background:rgba(0,212,170,.12);color:var(--accent)}
.b-user{background:rgba(124,110,245,.12);color:var(--purple)}

/* ── MODAL ── */
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:200;
  display:none;align-items:center;justify-content:center}
.overlay.open{display:flex;animation:fadein .18s}
.modal{background:var(--s1);border:1px solid var(--border);border-radius:20px;
  padding:30px;width:500px;max-width:92vw;max-height:90vh;overflow-y:auto}
.modal-title{font-family:var(--display);font-weight:700;font-size:17px;margin-bottom:22px}
.mact{display:flex;gap:9px;margin-top:22px;justify-content:flex-end}
.frow{display:grid;grid-template-columns:1fr 1fr;gap:12px}

/* ── CREDENTIAL BOX ── */
.cred-box{background:var(--s2);border:1px solid var(--accent);border-radius:12px;padding:18px;margin-top:14px}
.cred-title{font-size:12px;color:var(--accent);font-weight:600;margin-bottom:10px;display:flex;align-items:center;gap:6px}
.cred-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
.cred-label{font-size:11px;color:var(--muted)}
.cred-val{font-family:var(--mono);font-size:13px;color:var(--text);background:var(--s3);
  padding:4px 10px;border-radius:6px;cursor:pointer;border:1px solid var(--border)}
.cred-val:hover{border-color:var(--accent)}
.cred-note{font-size:11px;color:var(--muted);margin-top:8px}

/* search */
.sbox{display:flex;gap:10px;margin-bottom:14px}
.sinput{flex:1;background:var(--s2);border:1px solid var(--border);border-radius:9px;
  padding:9px 14px;color:var(--text);font-family:var(--font);font-size:13px;outline:none}
.sinput:focus{border-color:var(--accent)}

/* divider */
.sec-div{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);
  padding:8px 22px;background:var(--s2);border-bottom:1px solid var(--border)}

/* toast */
.toast{position:fixed;bottom:28px;right:28px;background:var(--s1);border:1px solid var(--border);
  border-radius:11px;padding:13px 18px;font-size:13px;z-index:999;
  box-shadow:0 20px 40px rgba(0,0,0,.5);display:none;max-width:340px}
.toast.show{display:block;animation:up .25s}
.toast.ok{border-color:var(--accent);color:var(--accent)}
.toast.err{border-color:var(--red);color:var(--red)}
.toast.info{border-color:var(--blue);color:var(--blue)}

/* empty */
.empty{padding:40px;text-align:center;color:var(--muted);font-size:13px}

@media(max-width:1100px){.cgrid{grid-template-columns:repeat(2,1fr)}.crow{grid-template-columns:1fr}}
</style>
</head>
<body>

<!-- LOGIN -->
<div id="login-wrap">
  <div class="lcard">
    <div class="logo">FinControl Pro</div>
    <p class="logo-sub">Dashboard de Controle Financeiro Empresarial</p>
    <div class="field"><label>E-mail</label><input id="le" type="email" placeholder="seu@email.com" value="superadmin@fincontrol.com"></div>
    <div class="field"><label>Senha</label><input id="lp" type="password" value="super123"></div>
    <button class="btn btn-p" onclick="doLogin()">Entrar no Sistema</button>
    <div class="err" id="lerr"></div>
    <div style="margin-top:20px;padding-top:16px;border-top:1px solid var(--border)">
      <p style="font-size:11px;color:var(--muted);margin-bottom:8px">Contas de demonstração:</p>
      <div style="display:flex;flex-direction:column;gap:5px">
        <code style="font-size:11px;color:var(--yellow);background:var(--s2);padding:4px 8px;border-radius:6px">⭐ superadmin@fincontrol.com / super123</code>
        <code style="font-size:11px;color:var(--accent);background:var(--s2);padding:4px 8px;border-radius:6px">🏢 admin@techcorp.com / tech123</code>
        <code style="font-size:11px;color:var(--purple);background:var(--s2);padding:4px 8px;border-radius:6px">👤 joao@techcorp.com / joao123</code>
      </div>
    </div>
  </div>
</div>

<!-- APP -->
<div id="app">
  <aside class="sidebar">
    <div class="sb-logo">
      <div class="lt">FinControl</div>
      <div class="ls" id="sb-company">—</div>
    </div>
    <nav class="nav">
      <div class="ni active" onclick="showPage('dash')" id="nav-dash">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>Dashboard
      </div>
      <div class="ni" onclick="showPage('tx')" id="nav-tx">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>Transações
      </div>
      <div class="ni" onclick="showPage('users')" id="nav-users" style="display:none">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>Usuários
      </div>
      <div class="ni" onclick="showPage('companies')" id="nav-companies" style="display:none">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>Empresas
      </div>
      <div class="ni" onclick="showPage('reports')" id="nav-reports">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>Relatórios
      </div>
    </nav>
    <div class="sb-footer">
      <div class="sb-name" id="sb-name">—</div>
      <div id="sb-badge"></div>
      <button class="btn btn-g btn-sm" style="margin-top:10px;width:100%" onclick="doLogout()">Sair</button>
    </div>
  </aside>

  <main class="main">

    <!-- DASHBOARD -->
    <div class="page active" id="page-dash">
      <div class="ph"><div><div class="pt">Dashboard</div><div class="ps" id="dash-sub">Visão geral financeira</div></div></div>
      <div class="cgrid">
        <div class="card"><div class="ci">💰</div><div class="cl">Receitas</div><div class="cv" id="d-rec" style="color:var(--accent)">—</div><div class="cc">Total acumulado</div></div>
        <div class="card"><div class="ci">📉</div><div class="cl">Despesas</div><div class="cv" id="d-desp" style="color:var(--red)">—</div><div class="cc">Total acumulado</div></div>
        <div class="card"><div class="ci">📊</div><div class="cl">Saldo Líquido</div><div class="cv" id="d-saldo" style="color:var(--purple)">—</div><div class="cc" id="d-saldo-cc">—</div></div>
        <div class="card"><div class="ci">🔢</div><div class="cl" id="d-card4-label">Transações</div><div class="cv" id="d-card4" style="color:var(--yellow)">—</div><div class="cc" id="d-card4-sub">—</div></div>
      </div>
      <div class="crow">
        <div class="cc2"><div class="ct">Receitas vs Despesas (Mensal)</div><canvas id="chartM" height="200"></canvas></div>
        <div class="cc2"><div class="ct">Por Categoria</div><canvas id="chartC" height="200"></canvas></div>
      </div>
      <div class="tcard"><div class="th2"><div class="tt">Últimas Transações</div></div><div id="recent-wrap"></div></div>
    </div>

    <!-- TRANSACTIONS -->
    <div class="page" id="page-tx">
      <div class="ph">
        <div><div class="pt">Transações</div><div class="ps">Receitas e despesas registradas</div></div>
        <button class="btn btn-p" onclick="openTxModal()">+ Nova</button>
      </div>
      <div class="sbox">
        <input class="sinput" id="tx-q" placeholder="Buscar..." oninput="filterTx()">
        <select id="tx-tf" onchange="filterTx()" style="width:150px"><option value="">Todos</option><option value="receita">Receitas</option><option value="despesa">Despesas</option></select>
      </div>
      <div class="tcard"><div id="tx-wrap"></div></div>
    </div>

    <!-- USERS -->
    <div class="page" id="page-users">
      <div class="ph">
        <div><div class="pt">Usuários</div><div class="ps" id="users-sub">Gerenciamento de acessos</div></div>
        <button class="btn btn-p" onclick="openUserModal()">+ Novo Usuário</button>
      </div>
      <div class="tcard"><div id="users-wrap"></div></div>
    </div>

    <!-- COMPANIES (superadmin) -->
    <div class="page" id="page-companies">
      <div class="ph"><div><div class="pt">Empresas Clientes</div><div class="ps">Visão geral de todas as empresas</div></div></div>
      <div class="tcard"><div id="companies-wrap"></div></div>
    </div>

    <!-- REPORTS -->
    <div class="page" id="page-reports">
      <div class="ph"><div><div class="pt">Relatórios</div><div class="ps">Análise financeira detalhada</div></div></div>
      <div class="crow" style="grid-template-columns:1fr 1fr">
        <div class="cc2"><div class="ct">Receitas por Categoria</div><canvas id="chartRec" height="260"></canvas></div>
        <div class="cc2"><div class="ct">Despesas por Categoria</div><canvas id="chartDesp" height="260"></canvas></div>
      </div>
      <div class="cc2" style="margin-top:14px"><div class="ct">Evolução do Saldo Mensal</div><canvas id="chartSaldo" height="130"></canvas></div>
    </div>

  </main>
</div>

<!-- MODALS -->
<div class="overlay" id="tx-modal">
  <div class="modal">
    <div class="modal-title">Nova Transação</div>
    <div class="frow">
      <div class="field"><label>Tipo</label><select id="tx-type"><option value="receita">Receita</option><option value="despesa">Despesa</option></select></div>
      <div class="field"><label>Categoria</label><select id="tx-cat"><option>Vendas</option><option>Serviços</option><option>Salários</option><option>Aluguel</option><option>Marketing</option><option>Tecnologia</option><option>Logística</option><option>Operacional</option><option>Impostos</option><option>Outros</option></select></div>
    </div>
    <div class="field"><label>Descrição</label><input id="tx-desc" type="text" placeholder="Descreva..."></div>
    <div class="frow">
      <div class="field"><label>Valor (R$)</label><input id="tx-amt" type="number" min="0" step="0.01" placeholder="0,00"></div>
      <div class="field"><label>Data</label><input id="tx-date" type="date"></div>
    </div>
    <div class="field"><label>Status</label><select id="tx-st"><option value="concluido">Concluído</option><option value="pendente">Pendente</option></select></div>
    <div class="mact"><button class="btn btn-g" onclick="closeTxModal()">Cancelar</button><button class="btn btn-p" onclick="saveTx()">Salvar</button></div>
  </div>
</div>

<div class="overlay" id="user-modal">
  <div class="modal">
    <div class="modal-title" id="um-title">Novo Usuário</div>
    <div class="frow">
      <div class="field"><label>Nome Completo</label><input id="u-name" type="text" placeholder="Nome"></div>
      <div class="field"><label>Empresa</label><input id="u-company" type="text" placeholder="Nome da empresa" id="u-company"></div>
    </div>
    <div class="field"><label>E-mail</label><input id="u-email" type="email" placeholder="email@empresa.com"></div>
    <div class="frow">
      <div class="field"><label>Senha <span style="color:var(--muted)">(deixe vazio para gerar)</span></label><input id="u-pass" type="text" placeholder="Gerada automaticamente"></div>
      <div class="field" id="role-field"><label>Perfil</label>
        <select id="u-role">
          <option value="user">👤 Usuário</option>
          <option value="admin">🏢 Admin de Empresa</option>
          <option value="superadmin" id="opt-super" style="display:none">⭐ Super Admin</option>
        </select>
      </div>
    </div>
    <!-- credential result box -->
    <div id="cred-result" style="display:none" class="cred-box">
      <div class="cred-title">✅ Usuário criado com sucesso!</div>
      <div class="cred-row"><span class="cred-label">E-mail:</span><span class="cred-val" id="cred-email" onclick="copyVal(this)" title="Clique para copiar">—</span></div>
      <div class="cred-row"><span class="cred-label">Senha:</span><span class="cred-val" id="cred-pass" onclick="copyVal(this)" title="Clique para copiar">—</span></div>
      <div class="cred-note">⚠️ Anote as credenciais agora. Clique nos valores para copiar.</div>
    </div>
    <div class="err" id="uerr"></div>
    <div class="mact">
      <button class="btn btn-g" onclick="closeUserModal()">Fechar</button>
      <button class="btn btn-p" id="um-save-btn" onclick="saveUser()">Criar Usuário</button>
    </div>
  </div>
</div>

<!-- Reset password modal -->
<div class="overlay" id="reset-modal">
  <div class="modal" style="width:400px">
    <div class="modal-title">🔑 Nova Senha Gerada</div>
    <div class="cred-box">
      <div class="cred-title">Credenciais atualizadas</div>
      <div class="cred-row"><span class="cred-label">E-mail:</span><span class="cred-val" id="r-email" onclick="copyVal(this)">—</span></div>
      <div class="cred-row"><span class="cred-label">Nova Senha:</span><span class="cred-val" id="r-pass" onclick="copyVal(this)">—</span></div>
      <div class="cred-note">⚠️ Anote e envie ao usuário. Clique para copiar.</div>
    </div>
    <div class="mact"><button class="btn btn-p" onclick="document.getElementById('reset-modal').classList.remove('open')">OK, entendi</button></div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const fmt = v => 'R$ '+Number(v).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});
let allTx=[], SESSION={};
let cM,cC,cR,cD,cS;

// ── LOGIN ──
async function doLogin(){
  const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({email:document.getElementById('le').value, password:document.getElementById('lp').value})});
  const d=await r.json();
  if(d.ok){
    SESSION={name:d.name,role:d.role,company:d.company};
    document.getElementById('login-wrap').style.display='none';
    document.getElementById('app').style.display='block';
    applyRole(d.role, d.company);
    showPage('dash');
  } else document.getElementById('lerr').textContent=d.error;
}
async function doLogout(){ await fetch('/api/logout',{method:'POST'}); location.reload(); }
document.getElementById('lp').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin()});

function applyRole(role, company){
  document.getElementById('sb-name').textContent = SESSION.name;
  document.getElementById('sb-company').textContent = company||'—';
  const badges={superadmin:'rb-super',admin:'rb-admin',user:'rb-user'};
  const labels={superadmin:'⭐ Super Admin',admin:'🏢 Admin Empresa',user:'👤 Usuário'};
  document.getElementById('sb-badge').innerHTML=`<span class="role-badge ${badges[role]||'rb-user'}">${labels[role]||role}</span>`;
  if(role==='admin'||role==='superadmin') document.getElementById('nav-users').style.display='flex';
  if(role==='superadmin'){
    document.getElementById('nav-companies').style.display='flex';
    document.getElementById('opt-super').style.display='';
  }
}

// ── NAVIGATION ──
function showPage(name){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.ni').forEach(n=>n.classList.remove('active'));
  document.getElementById('page-'+name).classList.add('active');
  const nav=document.getElementById('nav-'+name);
  if(nav) nav.classList.add('active');
  const loaders={dash:loadDash,tx:loadTx,users:loadUsers,companies:loadCompanies,reports:loadReports};
  if(loaders[name]) loaders[name]();
}

// ── DASHBOARD ──
async function loadDash(){
  const d=await(await fetch('/api/summary')).json();
  document.getElementById('d-rec').textContent=fmt(d.receitas);
  document.getElementById('d-desp').textContent=fmt(d.despesas);
  document.getElementById('d-saldo').textContent=fmt(d.saldo);
  document.getElementById('d-saldo').style.color=d.saldo>=0?'var(--accent)':'var(--red)';
  document.getElementById('d-saldo-cc').textContent=d.saldo>=0?'✅ Saldo positivo':'⚠️ Saldo negativo';

  if(SESSION.role==='superadmin'){
    document.getElementById('dash-sub').textContent='Visão consolidada de todas as empresas';
    document.getElementById('d-card4-label').textContent='Total Usuários';
    document.getElementById('d-card4').textContent=d.total_users;
    document.getElementById('d-card4-sub').textContent=`${d.total_empresas} empresa(s) ativa(s)`;
  } else {
    document.getElementById('d-card4-label').textContent='Transações';
    document.getElementById('d-card4').textContent=d.total_transactions;
    document.getElementById('d-card4-sub').textContent='Total registradas';
  }

  const labels=d.monthly.map(m=>m.m);
  if(cM) cM.destroy();
  cM=new Chart(document.getElementById('chartM'),{type:'bar',
    data:{labels,datasets:[
      {label:'Receitas',data:d.monthly.map(m=>m.receitas),backgroundColor:'rgba(0,212,170,.65)',borderRadius:5},
      {label:'Despesas',data:d.monthly.map(m=>m.despesas),backgroundColor:'rgba(255,77,109,.65)',borderRadius:5}
    ]},
    options:{responsive:true,plugins:{legend:{labels:{color:'#64748b',font:{size:11}}}},
      scales:{x:{ticks:{color:'#64748b'},grid:{color:'#1a2030'}},y:{ticks:{color:'#64748b'},grid:{color:'#1a2030'}}}}});

  if(cC) cC.destroy();
  cC=new Chart(document.getElementById('chartC'),{type:'doughnut',
    data:{labels:d.by_category.map(c=>c.category),
      datasets:[{data:d.by_category.map(c=>c.total),
        backgroundColor:['#00d4aa','#7c6ef5','#ff4d6d','#ffbe0b','#3b9eff','#f59e0b','#10b981','#8b5cf6','#ef4444','#06b6d4']}]},
    options:{responsive:true,plugins:{legend:{labels:{color:'#64748b',font:{size:10}}}}}});

  const txR=await(await fetch('/api/transactions')).json();
  allTx=txR;
  renderRecentTx(txR.slice(0,8));
}

function renderRecentTx(rows){
  const w=document.getElementById('recent-wrap');
  if(!rows.length){w.innerHTML='<div class="empty">Nenhuma transação registrada</div>';return}
  const showCompany=SESSION.role==='superadmin';
  w.innerHTML=`<table><thead><tr><th>Data</th>${showCompany?'<th>Empresa</th>':''}
    <th>Descrição</th><th>Categoria</th><th>Tipo</th><th>Valor</th><th>Status</th></tr></thead>
  <tbody>${rows.map(t=>`<tr>
    <td style="font-family:var(--mono)">${t.date}</td>
    ${showCompany?`<td><span style="font-size:11px;color:var(--muted)">${t.company||'—'}</span></td>`:''}
    <td>${t.description||'—'}</td><td>${t.category}</td>
    <td><span class="badge b-${t.type}">${t.type}</span></td>
    <td style="font-family:var(--mono)">${fmt(t.amount)}</td>
    <td><span class="badge b-${t.status}">${t.status}</span></td>
  </tr>`).join('')}</tbody></table>`;
}

// ── TRANSACTIONS ──
async function loadTx(){
  allTx=await(await fetch('/api/transactions')).json();
  renderTxTable(allTx);
}
function renderTxTable(rows){
  const w=document.getElementById('tx-wrap');
  if(!rows.length){w.innerHTML='<div class="empty">Nenhuma transação</div>';return}
  const showCompany=SESSION.role==='superadmin';
  w.innerHTML=`<table><thead><tr><th>Data</th>${showCompany?'<th>Empresa</th>':''}
    <th>Descrição</th><th>Categoria</th><th>Tipo</th><th>Valor</th><th>Status</th><th></th></tr></thead>
  <tbody>${rows.map(t=>`<tr>
    <td style="font-family:var(--mono)">${t.date}</td>
    ${showCompany?`<td style="font-size:11px;color:var(--muted)">${t.company||'—'}</td>`:''}
    <td>${t.description||'—'}</td><td>${t.category}</td>
    <td><span class="badge b-${t.type}">${t.type}</span></td>
    <td style="font-family:var(--mono)">${fmt(t.amount)}</td>
    <td><span class="badge b-${t.status}">${t.status}</span></td>
    <td><button class="btn btn-r btn-sm" onclick="delTx(${t.id})">Excluir</button></td>
  </tr>`).join('')}</tbody></table>`;
}
function filterTx(){
  const q=document.getElementById('tx-q').value.toLowerCase();
  const tp=document.getElementById('tx-tf').value;
  renderTxTable(allTx.filter(t=>(!tp||t.type===tp)&&(!q||(t.description||'').toLowerCase().includes(q)||t.category.toLowerCase().includes(q))));
}
function openTxModal(){
  document.getElementById('tx-date').value=new Date().toISOString().split('T')[0];
  document.getElementById('tx-modal').classList.add('open');
}
function closeTxModal(){document.getElementById('tx-modal').classList.remove('open')}
async function saveTx(){
  const d={type:$v('tx-type'),category:$v('tx-cat'),description:$v('tx-desc'),
            amount:$v('tx-amt'),date:$v('tx-date'),status:$v('tx-st')};
  if(!d.amount||!d.date){showToast('Preencha todos os campos','err');return}
  await fetch('/api/transactions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});
  closeTxModal(); loadTx(); showToast('Transação criada!','ok');
}
async function delTx(id){
  if(!confirm('Excluir esta transação?'))return;
  await fetch('/api/transactions/'+id,{method:'DELETE'});
  loadTx(); showToast('Excluída','ok');
}

// ── USERS ──
async function loadUsers(){
  const users=await(await fetch('/api/users')).json();
  const w=document.getElementById('users-wrap');
  if(!users.length){w.innerHTML='<div class="empty">Nenhum usuário cadastrado</div>';return}

  const isSuper=SESSION.role==='superadmin';
  // group by company if superadmin
  if(isSuper){
    const groups={};
    users.forEach(u=>{
      const key=u.company||'Sem empresa';
      if(!groups[key]) groups[key]=[];
      groups[key].push(u);
    });
    let html='<table><thead><tr><th>Nome</th><th>E-mail</th><th>Perfil</th><th>Empresa</th><th>Criado em</th><th>Senha</th><th>Ações</th></tr></thead><tbody>';
    for(const [comp, list] of Object.entries(groups)){
      html+=`<tr><td colspan="7" class="sec-div">🏢 ${comp} <span style="color:var(--muted)">(${list.length} usuário${list.length>1?'s':''})</span></td></tr>`;
      html+=list.map(u=>userRow(u,true)).join('');
    }
    html+='</tbody></table>';
    w.innerHTML=html;
  } else {
    document.getElementById('users-sub').textContent=`Usuários da empresa: ${SESSION.company}`;
    w.innerHTML=`<table><thead><tr><th>Nome</th><th>E-mail</th><th>Perfil</th><th>Criado em</th><th>Senha</th><th>Ações</th></tr></thead>
    <tbody>${users.map(u=>userRow(u,false)).join('')}</tbody></table>`;
  }
}

function userRow(u, showCompany){
  const roleBadge={'superadmin':'b-super ⭐','admin':'b-admin 🏢','user':'b-user 👤'};
  const [cls,ico]=(roleBadge[u.role]||'b-user 👤').split(' ');
  const isSelf=(u.email===SESSION.email);
  return `<tr>
    <td><strong>${u.name}</strong></td>
    <td style="font-family:var(--mono);font-size:11px">${u.email}</td>
    <td><span class="badge ${cls}">${ico} ${u.role}</span></td>
    ${showCompany?`<td style="font-size:11px;color:var(--muted)">${u.company||'—'}</td>`:''}
    <td style="font-family:var(--mono);font-size:11px">${(u.created_at||'').split(' ')[0]}</td>
    <td>
      ${u.plain_password
        ? `<span class="cred-val" onclick="copyVal(this)" title="Clique para copiar" style="font-size:11px">${u.plain_password}</span>`
        : `<span style="color:var(--muted);font-size:11px">oculta</span>`}
    </td>
    <td style="display:flex;gap:6px;align-items:center">
      <button class="btn btn-b btn-sm" onclick="resetPw(${u.id})">🔑 Reset</button>
      ${u.role!=='superadmin'?`<button class="btn btn-r btn-sm" onclick="delUser(${u.id})">Excluir</button>`:''}
    </td>
  </tr>`;
}

function openUserModal(){
  document.getElementById('cred-result').style.display='none';
  document.getElementById('uerr').textContent='';
  document.getElementById('um-save-btn').style.display='';
  ['u-name','u-email','u-pass','u-company'].forEach(id=>document.getElementById(id).value='');
  // Admin de empresa só cria users, não admin
  if(SESSION.role==='admin'){
    document.getElementById('u-role').value='user';
    document.getElementById('role-field').style.display='none';
    document.getElementById('u-company').value=SESSION.company;
    document.getElementById('u-company').readOnly=true;
  } else {
    document.getElementById('role-field').style.display='';
    document.getElementById('u-company').readOnly=false;
  }
  document.getElementById('user-modal').classList.add('open');
}
function closeUserModal(){document.getElementById('user-modal').classList.remove('open')}

async function saveUser(){
  const d={name:$v('u-name'),email:$v('u-email'),password:$v('u-pass'),
            company:$v('u-company'),role:$v('u-role')};
  const r=await fetch('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});
  const res=await r.json();
  if(res.ok){
    // show credential box
    document.getElementById('cred-email').textContent=res.email;
    document.getElementById('cred-pass').textContent=res.plain_password;
    document.getElementById('cred-result').style.display='block';
    document.getElementById('um-save-btn').style.display='none';
    loadUsers();
    showToast(`Usuário ${res.email} criado!`,'ok');
  } else {
    document.getElementById('uerr').textContent=res.error;
  }
}

async function delUser(id){
  if(!confirm('Excluir este usuário?'))return;
  const r=await fetch('/api/users/'+id,{method:'DELETE'});
  const d=await r.json();
  if(d.ok){loadUsers();showToast('Usuário removido','ok');}
  else showToast(d.error,'err');
}

async function resetPw(id){
  if(!confirm('Gerar nova senha para este usuário?'))return;
  const r=await fetch('/api/users/'+id+'/reset-password',{method:'POST'});
  const d=await r.json();
  if(d.ok){
    document.getElementById('r-email').textContent=d.email;
    document.getElementById('r-pass').textContent=d.plain_password;
    document.getElementById('reset-modal').classList.add('open');
    loadUsers();
  }
}

// ── COMPANIES ──
async function loadCompanies(){
  const companies=await(await fetch('/api/companies')).json();
  const w=document.getElementById('companies-wrap');
  if(!companies.length){w.innerHTML='<div class="empty">Nenhuma empresa cadastrada</div>';return}
  w.innerHTML=`<table><thead><tr><th>Empresa</th><th>ID</th><th>Usuários</th><th>Transações</th></tr></thead>
  <tbody>${companies.map(c=>`<tr>
    <td><strong>${c.company||'—'}</strong></td>
    <td style="font-family:var(--mono);color:var(--muted)">#${c.company_id}</td>
    <td>${c.total_users}</td>
    <td>${c.total_tx}</td>
  </tr>`).join('')}</tbody></table>`;
}

// ── REPORTS ──
async function loadReports(){
  const d=await(await fetch('/api/summary')).json();
  const rec=d.by_category.filter(c=>c.type==='receita');
  const desp=d.by_category.filter(c=>c.type==='despesa');
  const pal=['#00d4aa','#7c6ef5','#ffbe0b','#3b9eff','#10b981','#f59e0b','#8b5cf6'];
  if(cR) cR.destroy();
  cR=new Chart(document.getElementById('chartRec'),{type:'pie',data:{labels:rec.map(c=>c.category),
    datasets:[{data:rec.map(c=>c.total),backgroundColor:pal}]},
    options:{plugins:{legend:{labels:{color:'#64748b',font:{size:10}}}}}});
  if(cD) cD.destroy();
  cD=new Chart(document.getElementById('chartDesp'),{type:'pie',data:{labels:desp.map(c=>c.category),
    datasets:[{data:desp.map(c=>c.total),backgroundColor:[...pal].reverse()}]},
    options:{plugins:{legend:{labels:{color:'#64748b',font:{size:10}}}}}});
  if(cS) cS.destroy();
  cS=new Chart(document.getElementById('chartSaldo'),{type:'line',
    data:{labels:d.monthly.map(m=>m.m),datasets:[{label:'Saldo',
      data:d.monthly.map(m=>m.receitas-m.despesas),borderColor:'#7c6ef5',
      backgroundColor:'rgba(124,110,245,.12)',fill:true,tension:.4,pointBackgroundColor:'#7c6ef5'}]},
    options:{responsive:true,plugins:{legend:{labels:{color:'#64748b'}}},
      scales:{x:{ticks:{color:'#64748b'},grid:{color:'#1a2030'}},y:{ticks:{color:'#64748b'},grid:{color:'#1a2030'}}}}});
}

// ── UTILS ──
function $v(id){return document.getElementById(id).value}
function showToast(msg,type='ok'){
  const t=document.getElementById('toast');
  t.textContent=msg; t.className='toast show '+type;
  setTimeout(()=>t.className='toast',3500);
}
function copyVal(el){
  navigator.clipboard.writeText(el.textContent).then(()=>showToast('Copiado!','info'));
}
document.querySelectorAll('.overlay').forEach(o=>o.addEventListener('click',e=>{if(e.target===o)o.classList.remove('open')}));
</script>
</body>
</html>"""

@app.route("/")
def index(): return HTML

# Inicializa DB ao carregar (necessário para gunicorn)
init_db()

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
