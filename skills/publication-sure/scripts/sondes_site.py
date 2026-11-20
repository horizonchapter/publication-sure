"""Sondes dynamiques maison (esprit OWASP ZAP baseline) sur un site LOCAL seulement. Aucune dépendance.
Usage : python sondes_site.py <http://127.0.0.1:port/ | dossier build> [--rapport f.md]
        python sondes_site.py --selftest
Un dossier build est servi en local comme un hébergeur (fichier _headers appliqué, /page -> page.html, 404.html).
Refuse toute URL hors localhost. Les rafales (limite de tentatives) écrivent dans l'app testée : local seulement.
"""
import argparse, functools, http.server, os, re, secrets, sys, tempfile, threading, urllib.error, urllib.request
from fnmatch import fnmatch
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent))
from scan_securite import SECRETS, MOTS, jwt_service_role  # noqa: E402

LOCAL = {"127.0.0.1", "localhost", "::1", "[::1]"}
SENSIBLES = ["/.env", "/.env.local", "/.env.production", "/.git/HEAD", "/.git/config", "/.npmrc", "/backup.zip", "/site.zip",
             "/dump.sql", "/db.sqlite", "/database.sqlite", "/wp-config.php.bak", "/phpinfo.php", "/server-status", "/.htpasswd"]
BAVARDS = ["/package.json", "/.DS_Store", "/config.json", "/.vscode/settings.json", "/composer.json"]
ADMIN = ["/admin", "/admin/", "/administrator", "/dashboard", "/wp-admin/", "/backoffice", "/api/admin", "/manage", "/panel"]
TRACE = r"Traceback \(most recent call last\)|\bat [\w.$<>]+ \([^)]*:\d+:\d+\)|SQLSTATE|ORA-\d{5}|Warning: .+ on line \d+|Fatal error:|node_modules[/\\]|Exception in thread|stack ?trace"
ATTAQUANT = "https://attaquant.example"


class _SansRedirection(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a):
        return None


_OUVRIR = urllib.request.build_opener(_SansRedirection).open


def requete(url, methode="GET", entetes=None, corps=None):
    r = urllib.request.Request(url, method=methode, data=corps, headers={"User-Agent": "sondes-publication-sure", **(entetes or {})})
    try:
        with _OUVRIR(r, timeout=10) as x:
            return x.status, x.headers, x.read(3_000_000).decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read(300_000).decode("utf-8", "ignore")
    except OSError:
        return 0, {}, ""


class _Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.liens, self.scripts, self.formes, self.mdp, self.champs = [], [], [], False, {}

    def handle_starttag(self, tag, a):
        a = dict(a)
        if tag == "a" and a.get("href"):
            self.liens.append(a["href"])
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "form":
            self.formes.append(((a.get("method") or "get").lower(), a.get("action") or ""))
        elif tag in ("input", "textarea", "select") and self.formes and a.get("name"):
            self.champs.setdefault(self.formes[-1], set()).add(a["name"])  # champs du dernier formulaire ouvert
        if tag == "input" and (a.get("type") or "").lower() == "password":
            self.mdp = True


# --- serveur local qui imite l'hébergeur (Cloudflare Pages / Netlify) ---
def _regles(dist):
    f, regles = Path(dist) / "_headers", []
    if f.exists():
        for l in f.read_text(encoding="utf-8").splitlines():
            if not l.strip() or l.lstrip().startswith("#"):
                continue
            if not l[0].isspace():
                regles.append((l.strip(), []))
            elif regles and ":" in l:
                k, v = l.split(":", 1)
                regles[-1][1].append((k.strip(), v.strip()))
    return regles


class _Servi(http.server.SimpleHTTPRequestHandler):
    regles = []
    server_version, sys_version = "hebergeur-local", ""  # l'en-tête Server de ce serveur de test n'est pas celui de l'hébergeur

    def translate_path(self, path):
        p = super().translate_path(path)
        return p + ".html" if not os.path.exists(p) and os.path.isfile(p + ".html") else p

    def send_error(self, code, message=None, explain=None):
        d = Path(self.directory)
        page = d / "404.html" if (d / "404.html").exists() else d / "index.html"
        if code != 404 or self.command not in ("GET", "HEAD") or not page.exists():
            return super().send_error(code, message, explain)
        corps = page.read_bytes()
        self.send_response(404 if page.name == "404.html" else 200)  # sans 404.html : repli SPA, comme Cloudflare Pages
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(corps)))
        self.end_headers()
        if self.command == "GET":
            self.wfile.write(corps)

    def end_headers(self):
        chemin = self.path.split("?")[0]
        for motif, hs in self.regles:
            if fnmatch(chemin, motif.split("?")[0]):
                for k, v in hs:
                    self.send_header(k, v)
        super().end_headers()

    def log_message(self, *a):
        pass


class _Serveur(http.server.ThreadingHTTPServer):
    def handle_error(self, *a):  # coupures du client (rafales) : bruit sans effet
        pass


def servir(dist):
    h = functools.partial(type("H", (_Servi,), {"regles": _regles(dist)}), directory=str(dist))
    srv = _Serveur(("127.0.0.1", 0), h)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


# --- sondes ---
def explorer(base, limite=40):
    hote, a_voir, pages, scripts, formes, mdp = urlparse(base).netloc, [base], {}, set(), {}, False
    reponses = []
    while a_voir and len(pages) < limite:
        u = a_voir.pop(0).split("#")[0]
        if u in pages:
            continue
        st, h, corps = requete(u)
        pages[u] = corps if st == 200 and "html" in (h.get("Content-Type") or "") else ""
        reponses.append((u, st, h))
        if not pages[u]:
            continue
        p = _Page()
        p.feed(corps)
        mdp |= p.mdp
        scripts |= {urljoin(u, s) for s in p.scripts if urlparse(urljoin(u, s)).netloc == hote}
        for m, a in p.formes:  # formes = {(méthode, url absolue): noms des champs}
            formes.setdefault((m, urljoin(u, a)), set()).update(p.champs.get((m, a), ()))
        for l in p.liens:
            v = urljoin(u, l).split("#")[0]
            if urlparse(v).netloc == hote and v not in pages and not re.search(r"\.(png|jpe?g|webp|gif|svg|pdf|zip|mp4|ico|xml|txt)$", v, re.I):
                a_voir.append(v)
    return {u: c for u, c in pages.items() if c}, scripts, formes, mdp, reponses


def _soft404(base):
    st, _, corps = requete(urljoin(base, "/inexistant-" + secrets.token_hex(6)))
    return st, corps


def _existe(base, chemin, ref):
    st, _, corps = requete(urljoin(base, chemin))
    return st == 200 and corps != ref[1] and corps.strip() != "", corps


def sonder(url):
    """Renvoie (lignes, pages) ; ligne = (point, statut, info, détails, correction)."""
    if urlparse(url).hostname not in LOCAL:
        raise SystemExit(f"Refus : {url} n'est pas en localhost. Les sondes ne visent que vos sites servis en local.")
    base = url if url.endswith("/") else url + "/"
    pages, scripts, formes, mdp, reponses = explorer(base)
    L = []
    if not pages:
        return [("S0 Site joignable", "RESTE À FAIRE", f"aucune page HTML sur {base}", [], "lancer le site en local puis relancer")], {}
    ref = _soft404(base)
    st0, h0, _ = requete(base)

    # en-têtes de la page d'accueil
    h = {k.lower(): v for k, v in h0.items()}
    csp = h.get("content-security-policy", "")
    manque = [n for n, ok in [("Content-Security-Policy", csp), ("X-Content-Type-Options", h.get("x-content-type-options", "").lower() == "nosniff"),
                              ("Referrer-Policy", h.get("referrer-policy")), ("anti-iframe (X-Frame-Options ou frame-ancestors)", h.get("x-frame-options") or "frame-ancestors" in csp)] if not ok]
    L.append(("S1 En-têtes de sécurité", "RESTE À FAIRE" if manque else "OK", "manquent : " + ", ".join(manque) if manque else "CSP, nosniff, Referrer-Policy, anti-iframe présents", manque,
              "site statique : _headers (Cloudflare/Netlify) ; serveur applicatif : le poser dans le code (Express : helmet ; nginx : add_header) : Content-Security-Policy: default-src 'self'; frame-ancestors 'none' | X-Content-Type-Options: nosniff | Referrer-Policy: strict-origin-when-cross-origin"))
    faibles = [x for x in ("'unsafe-eval'", "'unsafe-inline'") if x in csp.split("style-src")[0]]
    faibles += [] if h.get("permissions-policy") else ["Permissions-Policy absente"]
    if faibles:
        L.append(("S1b CSP et Permissions-Policy", "À VÉRIFIER", "durcissement possible", faibles, "retirer unsafe-eval/unsafe-inline de script-src si possible ; ajouter Permissions-Policy: camera=(), microphone=(), geolocation=()"))
    bavard = [f"{k}: {h[k]}" for k in ("server", "x-powered-by", "x-aspnet-version") if k in h and re.search(r"\d", h[k])]
    if bavard:
        L.append(("S1c Version du serveur affichée", "À VÉRIFIER", "aide un attaquant à cibler une faille connue", bavard, "masquer la version (réglage de l'hébergeur ou du framework)"))

    # un POST par formulaire du site : le cookie de session n'arrive souvent qu'en réponse au POST (connexion)
    hote = urlparse(base).netloc
    for m, a in [f for f in formes if f[0] == "post" and urlparse(f[1]).netloc == hote][:3]:
        corps = "&".join(f"{c}=sonde" for c in sorted(formes[(m, a)] or {"email", "password"})).encode()
        st, hh, _ = requete(a, "POST", {"Content-Type": "application/x-www-form-urlencoded"}, corps)
        reponses.append((a, st, hh))

    # cookies
    pb_c = set()
    for u, st, hh in reponses:
        for c in (hh.get_all("Set-Cookie") or []) if hasattr(hh, "get_all") else []:
            nom, bas = c.split("=")[0].strip(), c.lower()
            manquent = [f for f in ("secure", "httponly", "samesite") if f not in bas]
            if manquent:
                pb_c.add((re.search(r"sess|sid|token|auth|jwt|login", nom, re.I) is not None, f"{nom} sans {', '.join(manquent)}"))
    L.append(("S2 Cookies", "RESTE À FAIRE" if any(g for g, _ in pb_c) else ("À VÉRIFIER" if pb_c else "OK"),
              f"{len(pb_c)} cookie(s) mal protégé(s)" if pb_c else "aucun cookie mal protégé", [t for _, t in pb_c],
              "poser les cookies avec Secure; HttpOnly; SameSite=Lax (Strict pour la session)"))

    # CORS : origine étrangère renvoyée ?
    cibles = [base] + sorted({urljoin(base, m) for s in scripts for m in re.findall(r"[\"'`](/api/[\w/-]+)", requete(s)[2])})[:5]
    pb_cors = []
    for c in cibles:
        _, hc, _ = requete(c, entetes={"Origin": ATTAQUANT})
        acao, cred = (hc.get("Access-Control-Allow-Origin") or ""), (hc.get("Access-Control-Allow-Credentials") or "").lower() == "true"
        if acao == ATTAQUANT or (acao == "*" and cred):
            pb_cors.append(f"{urlparse(c).path} renvoie l'origine {acao}{' avec cookies' if cred else ''}")
    L.append(("S3 CORS", "RESTE À FAIRE" if pb_cors else "OK", "origine étrangère acceptée" if pb_cors else "aucune origine étrangère acceptée", pb_cors,
              "Access-Control-Allow-Origin limité à votre domaine exact, jamais l'origine renvoyée telle quelle avec Allow-Credentials"))

    # fichiers exposés
    graves, info = [], []
    for ch in SENSIBLES:
        ok, corps = _existe(base, ch, ref)
        if ok and not (ch.startswith("/.git/HEAD") and not re.match(r"ref:|[0-9a-f]{40}", corps)) and not (ch.startswith("/.env") and not re.search(r"^\s*\w+\s*=", corps, re.M)):
            graves.append(ch)
    info = [ch for ch in BAVARDS if _existe(base, ch, ref)[0]]
    L.append(("S4 Fichiers sensibles exposés", "RESTE À FAIRE" if graves else ("À VÉRIFIER" if info else "OK"),
              f"{len(graves)} sensible(s), {len(info)} bavard(s)" if graves or info else "aucun .env, .git, sauvegarde ni dump servi", graves + info,
              "retirer ces fichiers du dossier publié (build) ; .env et .git ne doivent jamais être dans dist ; révoquer toute clé exposée"))

    # JS servi : secrets et source maps (ce qu'on voit avec F12)
    sec, cartes, indices = [], [], []
    for s in sorted(scripts):
        _, _, js = requete(s)
        nom = urlparse(s).path
        for n, m in SECRETS + MOTS:
            if re.search(m, js):
                sec.append(f"{nom} ({n})")
        if jwt_service_role(js):
            sec.append(f"{nom} (JWT Supabase service_role)")
        m = re.search(r"sourceMappingURL=([^\s*]+)", js)
        st_m, _, carte = requete(urljoin(s, m.group(1)) if m else s + ".map")
        if st_m == 200 and '"sources' in carte and carte != ref[1]:
            cartes.append(f"{nom}.map" + (" (code source complet)" if "sourcesContent" in carte else ""))
            for n, mo in SECRETS + MOTS:
                if re.search(mo, carte):
                    sec.append(f"{nom}.map ({n})")
        indices += [f"{nom} : clé publique {k}" for k in set(re.findall(r"\b(AIza[0-9A-Za-z_-]{35}|pk_live_\w{10}|sb_publishable_\w{6})", js))][:3]
    L.append(("S5 Secrets dans le JS servi", "RESTE À FAIRE" if sec else "OK", f"{len(sec)} trouvé(s) dans {len(scripts)} script(s)" if sec else f"{len(scripts)} script(s) lus, aucun secret", sec,
              "déplacer la clé côté serveur (fonction serveur, variable d'environnement non publique) puis la RÉVOQUER chez le fournisseur"))
    L.append(("S6 Source maps publiques", "RESTE À FAIRE" if cartes else "OK", "le code source est lisible dans F12 > Sources" if cartes else "aucune source map servie", cartes,
              "désactiver les source maps du build de production (Vite : build.sourcemap=false ; Astro : vite.build.sourcemap=false) ou les retirer de dist"))
    if indices:
        L.append(("S6b Clés publiques visibles", "À VÉRIFIER", "normal si clé publique, à condition qu'elle soit restreinte", indices[:5], "restreindre la clé (domaines autorisés, RLS, quotas) chez le fournisseur"))

    # messages d'erreur bavards
    trace = []
    for ch in ["/inexistant-" + secrets.token_hex(4) + "?x=%27%22%3C", "/api/" + secrets.token_hex(4)]:
        st, _, corps = requete(urljoin(base, ch))
        if re.search(TRACE, corps, re.I):
            trace.append(ch.split("?")[0])
    for _, a in [f for f in formes if f[0] == "post"][:3]:
        st, _, corps = requete(a, "POST", {"Content-Type": "application/json"}, b"{\"x\":")
        if re.search(TRACE, corps, re.I):
            trace.append(urlparse(a).path + " (POST cassé)")
    L.append(("S7 Messages d'erreur", "RESTE À FAIRE" if trace else "OK", "trace interne montrée au visiteur" if trace else "aucune trace interne dans les erreurs", trace,
              "mode production : erreurs génériques au visiteur, détail seulement dans les journaux du serveur"))

    # XSS réfléchi
    jeton = "sonde" + secrets.token_hex(3)
    xss = []
    cibles_xss = [(u, set(re.findall(r"[?&](\w+)=", pages[u]))) for u in list(pages)[:12]]
    cibles_xss += [(a, ch) for (m, a), ch in formes.items() if m == "get" and urlparse(a).netloc == hote]  # formulaires GET (recherche)
    for u, params in cibles_xss:
        for p in sorted(params)[:6] + [x for x in ("q", "s", "search") if x not in params]:
            _, _, corps = requete(u.split("?")[0] + f"?{p}=%3C{jeton}%22%27%3E")
            if f"<{jeton}" in corps:
                xss.append(f"{urlparse(u).path}?{p}=")
                break
    L.append(("S8 XSS réfléchi", "RESTE À FAIRE" if xss else "OK", "paramètre recopié sans échappement" if xss else "aucun paramètre recopié tel quel", xss,
              "échapper toute donnée d'URL ou de formulaire avant affichage (textContent, pas innerHTML ; échappement du framework)"))

    # routes admin
    ouvertes, connexion = [], []
    for ch in ADMIN:
        st, _, corps = requete(urljoin(base, ch))
        if st == 200 and corps != ref[1] and corps.strip():
            (connexion if re.search(r"type=[\"']?password", corps, re.I) else ouvertes).append(ch)
    L.append(("S9 Routes admin", "RESTE À FAIRE" if ouvertes else ("À VÉRIFIER" if connexion else "OK"),
              "admin accessible sans connexion" if ouvertes else ("page de connexion admin trouvée" if connexion else "aucune route admin ouverte"), ouvertes + connexion,
              "protéger côté serveur (session + rôle) ; une URL cachée n'est pas une protection ; MFA pour l'admin"))

    # limite de tentatives : 30 POST rapides
    points = [a for m, a in formes if m == "post" and urlparse(a).netloc == urlparse(base).netloc]
    points += [c for c in cibles[1:] if c not in points]
    sans_limite, testes, morts = [], 0, []
    for a in points[:3]:
        codes = [requete(a, "POST", {"Content-Type": "application/x-www-form-urlencoded"}, b"email=test%40exemple.fr&password=sonde&message=sonde")[0] for _ in range(30)]
        if codes[0] in (0, 404, 405, 501):
            if ("post", a) in formes:
                morts.append(f"{urlparse(a).path or '/'} répond {codes[0]}")
            continue
        testes += 1
        if not any(c in (429, 403, 503) for c in codes):
            sans_limite.append(f"{urlparse(a).path} : 30 POST acceptés ({codes[0]})")
    L.append(("S10 Limite de tentatives", "RESTE À FAIRE" if sans_limite else ("OK" if testes else ("À VÉRIFIER" if mdp else "NON APPLICABLE")),
              f"{testes} point(s) POST testé(s)" if testes else ("formulaire de mot de passe vu mais aucun POST testable en local" if mdp else "aucun formulaire POST ni API joignable"), sans_limite,
              "limite par IP (Cloudflare Rate Limiting gratuit, ou compteur dans la fonction serveur) : 429 après 5 à 10 essais par minute ; Turnstile sur les formulaires"))
    if morts:  # build servi en local : 501 = rien ne traite le POST ici (normal si l'hébergeur le fait : Netlify Forms, fonction)
        L.append(("S10b Formulaires sans destination", "À VÉRIFIER", "formulaire POST que rien ne traite en local", morts,
                  "brancher le formulaire (fonction serveur, Netlify Forms, Formspree) puis envoyer un vrai message de test sur la préproduction ; sinon retirer le formulaire"))
    return L, pages


def rapport(lignes, cible):
    v = "ÉCHOUE" if any(l[1] == "RESTE À FAIRE" for l in lignes) else "PASSE"
    out = [f"Verdict sondes : {v}", "", f"Cible : {cible}", "", "| Point | Statut | Détail | Correction |", "|---|---|---|---|"]
    out += [f"| {n} | {s} | {i}{' : ' + '; '.join(d[:8]) if d else ''} | {c if s not in ('OK', 'NON APPLICABLE') else ''} |" for n, s, i, d, c in lignes]
    return v, "\n".join(out)


def selftest():
    with tempfile.TemporaryDirectory() as t:
        d = Path(t)
        (d / "index.html").write_text('<a href="/contact">c</a><script src="/app.js"></script>', encoding="utf-8")
        (d / "contact.html").write_text("<p>contact</p>", encoding="utf-8")
        (d / "app.js").write_text("var k='" + "sk_" + "live_" + "b2" * 12 + "';\n//# sourceMappingURL=app.js.map\n", encoding="utf-8")
        (d / "app.js.map").write_text('{"version":3,"sources":["src/app.ts"],"sourcesContent":["x"]}', encoding="utf-8")
        (d / ".env").write_text("SECRET=1\n", encoding="utf-8")
        (d / "admin.html").write_text("<h1>Tableau admin</h1>", encoding="utf-8")
        srv, url = servir(d)
        L, pages = sonder(url)
        s = {l[0].split()[0]: l[1] for l in L}
        assert len(pages) == 2 and s["S1"] == "RESTE À FAIRE" and s["S4"] == "RESTE À FAIRE" and s["S5"] == "RESTE À FAIRE", L
        assert s["S6"] == "RESTE À FAIRE" and s["S9"] == "RESTE À FAIRE", L
        srv.shutdown()
        d = Path(t) / "propre"
        d.mkdir()
        (d / "index.html").write_text('<a href="/contact">c</a><script src="/app.js"></script>', encoding="utf-8")
        (d / "contact.html").write_text('<form method="post" action="/envoyer"><input name="email"></form>', encoding="utf-8")
        (d / "app.js").write_text("var ok=1;\n", encoding="utf-8")
        (d / "404.html").write_text("introuvable", encoding="utf-8")
        (d / "_headers").write_text("/*\n  Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: no-referrer\n  Permissions-Policy: camera=()\n", encoding="utf-8")
        srv, url = servir(d)
        L, _ = sonder(url)
        assert rapport(L, url)[0] == "PASSE", L
        assert any(l[0].startswith("S10b") for l in L), L  # formulaire POST qui ne mène à rien : signalé
        srv.shutdown()

    class _App(http.server.BaseHTTPRequestHandler):  # app piégée : cookie posé au POST seulement, recherche GET non échappée
        def _envoyer(self, corps, cookie=None):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(corps.encode())

        def do_GET(self):
            q = parse_qs(urlparse(self.path).query).get("q", [""])[0] if self.path.startswith("/recherche") else ""
            self._envoyer('<form method="post" action="/login"><input name="email"><input type="password" name="pwd"></form>'
                          f'<form action="/recherche"><input name="q"></form><p>{q}</p>')

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self._envoyer("ok", "session=abc")

        def log_message(self, *a):
            pass

    srv = _Serveur(("127.0.0.1", 0), _App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    s = {l[0].split()[0]: l[1] for l in sonder(f"http://127.0.0.1:{srv.server_address[1]}/")[0]}
    srv.shutdown()
    assert s["S2"] == "RESTE À FAIRE" and s["S8"] == "RESTE À FAIRE" and s["S10"] == "RESTE À FAIRE", s
    try:
        sonder("https://exemple.com/")
        raise AssertionError("URL distante acceptée")
    except SystemExit:
        pass
    print("selftest sondes OK")


if __name__ == "__main__":
    a = argparse.ArgumentParser()
    a.add_argument("cible", nargs="?")
    a.add_argument("--rapport")
    a.add_argument("--selftest", action="store_true")
    o = a.parse_args()
    if o.selftest:
        selftest(); sys.exit(0)
    if not o.cible:
        sys.exit("Cible manquante")
    srv = None
    if Path(o.cible).is_dir():
        srv, url = servir(o.cible)
    else:
        url = o.cible
    L, _ = sonder(url)
    v, txt = rapport(L, o.cible)
    print(txt)
    if o.rapport:
        Path(o.rapport).parent.mkdir(parents=True, exist_ok=True)
        Path(o.rapport).write_text(txt + "\n", encoding="utf-8")
    sys.exit(1 if v == "ÉCHOUE" else 0)
