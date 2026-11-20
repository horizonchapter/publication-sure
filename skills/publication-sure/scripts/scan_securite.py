"""Contrôle complet avant mise en ligne : sécurité statique (source + build + historique git), sondes dynamiques en local
(sondes_site.py) et contrôle légal FR/UE (controle_legal.py). Aucune dépendance, aucun scan hors localhost.
Usage : python scan_securite.py <dossier source> [--dist <build>] [--url <http://127.0.0.1:port/>] [--ecommerce | --pas-ecommerce] [--rapport <fichier.md>]
        python scan_securite.py --selftest
--dist : le build est servi en local et sondé ; --url locale : sonde un serveur de dev déjà lancé.
--url distante : une seule requête d'en-têtes (comme un visiteur), aucune sonde.
Verdict PASSE / ÉCHOUE en 1re ligne ; code 1 si ÉCHOUE. N'affiche jamais la valeur d'un secret (fichier:ligne et type seulement).
"""
import argparse, base64, json, os, re, shutil, subprocess, sys, tempfile, urllib.request
from pathlib import Path
from urllib.parse import urlparse

# a_valider et securite : nos propres rapports, qui citent les mots cherchés (sinon le 2e passage se contamine)
IGNORE = {"node_modules", ".git", ".astro", ".wrangler", ".venv", "venv", "__pycache__", ".next", ".cache", "a_valider", "securite"}
TEXTE = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".html", ".astro", ".vue", ".svelte", ".py", ".env",
         ".toml", ".yaml", ".yml", ".txt", ".md", ".css", ".map", ".sh", ".ps1", ""}
SECRETS = [
    ("clé Stripe secrète", r"\b[sr]k_(live|test)_[0-9A-Za-z]{16,}"),
    ("secret de webhook Stripe", r"\bwhsec_[0-9A-Za-z]{16,}"),
    ("clé AWS", r"\bAKIA[0-9A-Z]{16}\b"),
    ("clé privée", r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ("jeton GitHub", r"\bgh[pousr]_[0-9A-Za-z]{30,}"),
    ("jeton Slack", r"\bxox[abprs]-[0-9A-Za-z-]{10,}"),
    ("clé Anthropic", r"\bsk-ant-[0-9A-Za-z_-]{20,}"),
    ("clé OpenAI", r"\bsk-(proj-)?[0-9A-Za-z_-]{32,}"),
    ("clé Resend", r"\bre_[0-9A-Za-z]{8}_[0-9A-Za-z]{16,}"),
    ("clé SendGrid", r"\bSG\.[0-9A-Za-z_-]{20,}\.[0-9A-Za-z_-]{20,}"),
    ("jeton Shopify", r"\bshp(at|ss|ca|pa)_[0-9a-fA-F]{32}"),
    ("clé Google service account", r"\"private_key_id\"\s*:"),
    ("secret dans une variable publique", r"\b(NEXT_PUBLIC|VITE|PUBLIC|REACT_APP|EXPO_PUBLIC)_\w*(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD)\w*"),
]
# un mot, pas une clé : bloquant dans le build livré, simple indice dans la source (code serveur, docs)
MOTS = [("service_role Supabase", r"service_role"), ("sb_secret Supabase", r"\bsb_secret_")]
# affectation qui ressemble à un secret : à regarder, jamais bloquant seul (trop de faux positifs dans du JS minifié)
GENERIQUE = [("valeur de type secret", r"(?i)\b(api[_-]?key|secret|passw(or)?d|private[_-]?key|access[_-]?token)\b[\"']?\s*[:=]\s*[\"'][^\"'\s]{16,}[\"']")]
# mot de passe écrit en dur dans la source, sans seuil de longueur ; ignore lecture d'env, gabarits et valeurs vides
MDP = [("mot de passe en dur", r"(?i)(?<![\w-])(passw(or)?d|pwd|passwd|mot_?de_?passe|mdp|db_?pass\w*|admin_?pass\w*)\b[\"']?\s*[:=]\s*[\"'](?!<|\$\{|\{\{|process\.env|\*+[\"'])[^\"'\s]{4,}[\"']")]
JWT = re.compile(r"eyJ[\w-]{10,}\.(eyJ[\w-]{10,})\.[\w-]{10,}")


def jwt_service_role(texte):
    """Vrai si un JWT du texte porte role=service_role (clé Supabase qui contourne la RLS)."""
    for m in JWT.finditer(texte):
        try:
            if json.loads(base64.urlsafe_b64decode(m.group(1) + "==")).get("role") == "service_role":
                return True
        except ValueError:
            pass
    return False


def fichiers(racine):
    for d, sous, noms in os.walk(racine):
        sous[:] = [s for s in sous if s not in IGNORE]
        for n in noms:
            p = Path(d) / n
            if (p.suffix.lower() in TEXTE or n.startswith(".env")) and p.stat().st_size < 3_000_000:
                yield p


def chercher_secrets(racine, motifs=SECRETS, jwt=True):
    trouves = []
    for p in fichiers(racine):
        try:
            lignes = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for i, l in enumerate(lignes, 1):
            for nom, motif in motifs:
                if re.search(motif, l):
                    trouves.append(f"{p.relative_to(racine).as_posix()}:{i} ({nom})")
            if jwt and jwt_service_role(l):
                trouves.append(f"{p.relative_to(racine).as_posix()}:{i} (JWT Supabase service_role)")
    return trouves


def historique_git(src):
    """Secrets ajoutés dans l'historique du dépôt du projet (pas du coffre parent)."""
    git = shutil.which("git")
    if not git or not (Path(src) / ".git").exists():
        return None
    r = subprocess.run([git, "-C", str(src), "log", "-p", "--all", "--no-color", "-n", "300", "--format=@@commit %h"],
                       capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=180)
    trouves, commit = set(), "?"
    for l in r.stdout.splitlines():
        if l.startswith("@@commit "):
            commit = l.split()[1]
        elif l.startswith("+") and (any(re.search(m, l) for _, m in SECRETS) or jwt_service_role(l)):
            trouves.add(f"commit {commit}")
    return sorted(trouves)


def env_publies(src, dist):
    pb = []
    if dist:
        pb += [f"{p.relative_to(dist).as_posix()} publié dans le build" for p in Path(dist).rglob(".env*")]
    git = shutil.which("git")
    for p in Path(src).rglob(".env*"):
        if any(x in IGNORE for x in p.parts) or p.name.endswith((".example", ".sample")):
            continue
        ignore = git and subprocess.run([git, "-C", str(src), "check-ignore", "-q", str(p)], capture_output=True).returncode == 0
        if not ignore:
            pb.append(f"{p.relative_to(src).as_posix()} non ignoré par git")
    return pb


def build_bavard(dist):
    """Ce que F12 montre : source maps, dossier .git publié."""
    pb = [p.relative_to(dist).as_posix() for p in Path(dist).rglob("*.map")]
    pb += [f"{p.relative_to(dist).as_posix()} (sourceMappingURL)" for p in Path(dist).rglob("*.js")
           if "sourceMappingURL=" in p.read_text(encoding="utf-8", errors="ignore")[-400:]]
    pb += [".git publié"] if (Path(dist) / ".git").exists() else []
    return pb


def paquets(src):
    pj, lock = Path(src) / "package.json", Path(src) / "package-lock.json"
    if not pj.exists():
        return "NON APPLICABLE", "pas de package.json", []
    d = json.loads(pj.read_text(encoding="utf-8"))
    deps = {**d.get("dependencies", {}), **d.get("devDependencies", {})}
    if not lock.exists():  # sans lockfile : chaque nom est demandé au registre npm (lecture seule)
        npm = shutil.which("npm.cmd") or shutil.which("npm")
        inconnus = [x for x in list(deps)[:60] if npm and subprocess.run([npm, "view", x, "name"], capture_output=True, text=True, timeout=60).returncode != 0]
        return "RESTE À FAIRE", "package-lock.json absent" + ("" if npm else " ; npm absent, registre non consulté"), \
            ["package-lock.json absent : lancer npm install --package-lock-only puis npm audit, et committer le lockfile"] + [f"{x} : introuvable sur le registre npm (paquet inventé ?)" for x in inconnus]
    lk = json.loads(lock.read_text(encoding="utf-8")).get("packages", {})
    absents = [x for x in deps if not lk.get("node_modules/" + x, {}).get("resolved", "").startswith("https://registry.npmjs.org/")]
    npm = shutil.which("npm.cmd") or shutil.which("npm")
    graves = []
    if npm:
        r = subprocess.run([npm, "audit", "--json", "--omit=dev"], cwd=src, capture_output=True, text=True, timeout=180)
        try:
            v = json.loads(r.stdout).get("metadata", {}).get("vulnerabilities", {})
            graves = [f"npm audit : {v.get('critical', 0)} critique(s), {v.get('high', 0)} élevée(s)"] if v.get("critical") or v.get("high") else []
            info = f"{len(deps)} paquets du registre npm ; npm audit : {v.get('critical', 0)} critique, {v.get('high', 0)} élevée, {v.get('moderate', 0)} moyenne"
        except ValueError:
            info = "npm audit illisible (hors ligne ?)"
    else:
        info = "npm absent : audit non fait"
    pb = [f"{x} : pas résolu depuis registry.npmjs.org (paquet inventé ou privé ?)" for x in absents] + graves
    return ("RESTE À FAIRE" if pb else "OK"), info, pb


def entetes_distants(url):
    """Une requête GET comme un visiteur : en-têtes + redirection HTTPS. Pas de sonde."""
    voulus = ["content-security-policy", "x-content-type-options", "referrer-policy", "strict-transport-security"]
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "controle-avant-publication"}), timeout=20)
        vus = {k.lower() for k in r.headers.keys()}
        if url.startswith("https://"):
            try:
                if not urllib.request.urlopen(url.replace("https://", "http://", 1), timeout=20).geturl().startswith("https://"):
                    return "RESTE À FAIRE", "HTTP ne redirige pas vers HTTPS", ["redirection HTTPS"]
            except OSError:
                pass
    except OSError as e:
        return "À VÉRIFIER", f"URL injoignable : {e}", []
    manque = [h for h in voulus if h not in vus]
    return ("RESTE À FAIRE" if manque else "OK"), "en-têtes en ligne : " + ("manquent " + ", ".join(manque) if manque else "CSP, nosniff, Referrer-Policy, HSTS présents"), manque


def indices(src, motif):
    return [p.relative_to(src).as_posix() for p in fichiers(src) if p.suffix.lower() not in (".md", ".txt") and re.search(motif, p.read_text(encoding="utf-8", errors="ignore"), re.I)]


def scanner(src, dist=None, url=None, ecommerce=None):
    sys.path.insert(0, str(Path(__file__).parent))
    import sondes_site, controle_legal
    L = []
    b = chercher_secrets(dist, SECRETS + MOTS) if dist else []
    try:  # build rangé dans la source : même chemin pour les deux passages, puis dédoublonnage
        pre = Path(dist).resolve().relative_to(Path(src).resolve()).as_posix() + "/" if dist else None
        b = [(pre if pre != "./" else "") + x for x in b]
    except ValueError:
        pass
    s = list(dict.fromkeys(chercher_secrets(src) + b))
    L.append(("1 Clés secrètes (source + build)", "RESTE À FAIRE" if s else "OK", f"{len(s)} trouvée(s) (source{' + build' if dist else ''})", s,
              "sortir la clé du code (variable d'environnement côté serveur), puis la RÉVOQUER et en créer une neuve chez le fournisseur"))
    h = historique_git(src)
    if h is not None:
        f = Path(src) / "securite" / "cles-revoquees.txt"  # une ligne par commit dont la clé a été révoquée chez le fournisseur
        rev = set(re.findall(r"\b[0-9a-f]{7,40}\b", f.read_text(encoding="utf-8"))) if f.exists() else set()
        ouverts = [c for c in h if not any(c.split()[1].startswith(r[:7]) or r.startswith(c.split()[1]) for r in rev)]
        L.append(("1a Secrets dans l'historique git", "RESTE À FAIRE" if ouverts else "OK",
                  f"{len(ouverts)} commit(s) avec un secret non révoqué" if ouverts else (f"{len(h)} commit(s) avec un secret, clé révoquée (déclaré dans securite/cles-revoquees.txt)" if h else "300 derniers commits propres"), ouverts,
                  "révoquer la clé chez le fournisseur, puis écrire le commit dans <source>/securite/cles-revoquees.txt (l'effacer du code ne l'efface pas de l'historique) ; réécrire l'historique seulement si le dépôt est public"))
    pw = [x for x in chercher_secrets(src, MDP, jwt=False) if not re.search(r"\.(md|txt)$|(^|/)(tests?|__tests__|spec|i18n|locales?|lang|translations?)/|\.(test|spec)\.", x.split(":")[0])]
    if pw:
        L.append(("1f Mot de passe en dur (source)", "RESTE À FAIRE", f"{len(pw)} mot(s) de passe écrit(s) dans le code", pw[:8],
                  "lire le mot de passe dans une variable d'environnement côté serveur, puis le CHANGER (il reste dans l'historique git)"))
    m = [x for x in chercher_secrets(src, MOTS, jwt=False) if not x.split(":")[0].endswith(".md")]
    if m:
        L.append(("1c Mots secrets dans la source", "À VÉRIFIER", "vérifier que ces fichiers restent côté serveur", m[:8], "garder ces fichiers hors du build navigateur"))
    g = chercher_secrets(dist, GENERIQUE, jwt=False) if dist else []
    if g:
        L.append(("1d Valeurs de type secret dans le build", "À VÉRIFIER", "à lire une par une (souvent un faux positif)", g[:8], "si c'est un vrai secret : côté serveur puis révocation"))
    e = env_publies(src, dist)
    L.append(("1b Fichiers .env", "RESTE À FAIRE" if e else "OK", "aucun .env publié ni suivi par git" if not e else f"{len(e)} problème(s)", e,
              "ajouter .env* à .gitignore, retirer le fichier du build, révoquer les clés qu'il contient"))
    if dist:
        b = build_bavard(dist)
        L.append(("1e Build lisible dans F12", "RESTE À FAIRE" if b else "OK", "source maps ou .git dans le build" if b else "ni source map ni .git dans le build", b[:8],
                  "désactiver les source maps de production (Vite/Astro : build.sourcemap=false) et ne jamais copier .git dans dist"))
    supa = indices(src, r"supabase")
    L.append(("2 RLS", "À VÉRIFIER" if supa else "NON APPLICABLE", "Supabase utilisé : test anon sans session à faire" if supa else "pas de Supabase dans le code", supa[:5],
              "curl \"<URL_SUPABASE>/rest/v1/<table>?select=*\" -H \"apikey: <clé anon>\" sur chaque table : réponse [] attendue pour les données privées ; sinon activer la RLS et une politique auth.uid()"))
    adm = indices(src, r"[\"'/]admin\b")
    L.append(("3 Routes admin (source)", "À VÉRIFIER" if adm else "NON APPLICABLE", "routes admin dans le code : voir S9 et tester en navigation privée" if adm else "aucune route admin trouvée", adm[:5],
              "contrôle de session ET de rôle côté serveur sur chaque route admin"))
    wh = indices(src, r"webhook")
    sig = indices(src, r"(constructEvent|verifySignature|createHmac|timingSafeEqual|signature)")
    L.append(("5 Webhooks", ("RESTE À FAIRE" if not sig else "À VÉRIFIER") if wh else "NON APPLICABLE",
              "webhook sans vérification de signature visible" if wh and not sig else ("vérifier qu'un appel sans signature est refusé" if wh else "aucun webhook"), wh[:5],
              "vérifier la signature du fournisseur (Stripe : constructEvent avec whsec) avant de valider une commande ; appel sans signature = 400"))
    L.append(("6 Paquets inventés + npm audit", *paquets(src), "npm audit fix ; remplacer ou retirer tout paquet introuvable sur npmjs.com"))

    srv, pages, local = None, {}, url and urlparse(url).hostname in sondes_site.LOCAL
    if dist and not local and not (Path(dist) / "index.html").exists():
        L.append(("+ Sondes et légal", "NON APPLICABLE", "le build n'est pas un site (pas d'index.html) : app de bureau ou API ; donner --url du serveur local", [], ""))
        return ("ÉCHOUE" if any(l[1] == "RESTE À FAIRE" for l in L) else "PASSE"), L
    if dist or local:
        if not local:
            srv, url_s = sondes_site.servir(dist)
        try:
            ls, pages = sondes_site.sonder(url if local else url_s)
        finally:
            if srv:
                srv.shutdown()
        L += ls
    if url and not local:
        L.append(("+ En-têtes en ligne (1 requête)", *entetes_distants(url), "ajouter les en-têtes manquants dans _headers ; HSTS après validation du HTTPS"))
    if not (dist or url):
        L.append(("+ Sondes", "À VÉRIFIER", "ni build ni URL locale : rien n'a été sondé", [], "relancer avec --dist <build>"))
    if dist and not pages:
        pages = {p.relative_to(dist).as_posix(): p.read_text(encoding="utf-8", errors="ignore") for p in Path(dist).rglob("*.html")}
    L += controle_legal.controler(pages, ecommerce) if pages else [("L0 Contrôle légal", "À VÉRIFIER", "aucune page HTML lue", [], "relancer avec --dist")]
    return ("ÉCHOUE" if any(l[1] == "RESTE À FAIRE" for l in L) else "PASSE"), L


def rapport(verdict, lignes, src):
    av = sum(1 for l in lignes if l[1] == "À VÉRIFIER")
    nb = sum(1 for l in lignes if l[1] == "RESTE À FAIRE")
    out = [f"Verdict publication : {verdict}" + (f" ({nb} bloquant(s))" if nb else "") + (f" ; {av} point(s) À VÉRIFIER à tester à la main" if av else ""), "",
           f"Cible : {src}", "", "| Point | Statut | Détail | Correction proposée |", "|---|---|---|---|"]
    for nom, st, info, det, corr in sorted(lignes, key=lambda l: {"RESTE À FAIRE": 0, "À VÉRIFIER": 1}.get(l[1], 2)):
        out.append(f"| {nom} | {st} | {info}{' : ' + '; '.join(det[:8]) if det else ''} | {corr if st in ('RESTE À FAIRE', 'À VÉRIFIER') else ''} |")
    out += ["", "OK et NON APPLICABLE = fait par le script. À VÉRIFIER = test manuel à écrire dans securite/audit-AAAA-MM-JJ.md. RESTE À FAIRE = publication interdite.",
            "Volet légal : repérage automatique, pas un avis juridique ; en cas de doute, un professionnel (avocat, CCI)."]
    return "\n".join(out)


def selftest():
    with tempfile.TemporaryDirectory() as t:
        d = Path(t) / "a"
        d.mkdir()
        faux = lambda role: "eyJhbGciOiJIUzI1NiJ9." + base64.urlsafe_b64encode(('{"role":"%s","iss":"supabase"}' % role).encode()).decode().rstrip("=") + ".c2lnbmF0dXJlLWZhdXNzZQ"
        assert jwt_service_role(faux("service_role")) and not jwt_service_role(faux("anon"))
        (d / "app.js").write_text("const k = '" + "sk_" + "live_" + "a1" * 12 + "';\n", encoding="utf-8")
        (d / "index.html").write_text("<p>x</p>", encoding="utf-8")
        (d / "config.js").write_text('const password = "admin1";\nconst vide = { password: "" };\n', encoding="utf-8")
        (d / "package.json").write_text('{"dependencies": {"paquet-invente-zq9x7-sonde": "1.0.0"}}', encoding="utf-8")
        (d / "a_valider").mkdir()
        (d / "a_valider" / "securite.md").write_text("5 Webhooks RESTE À FAIRE ; password = \"exemple1\"", encoding="utf-8")
        v, l = scanner(str(d), dist=str(d), ecommerce=False)
        n = {x[0].split()[0]: x for x in l}
        assert v == "ÉCHOUE" and l[0][3] == ["app.js:1 (clé Stripe secrète)"], l[0]  # une seule fois, pas source + build
        assert n["1f"][3] == ["config.js:1 (mot de passe en dur)"], n.get("1f")  # 6 caractères suffisent ; a_valider/ ignoré
        assert n["5"][1] == "NON APPLICABLE" and n["6"][1] == "RESTE À FAIRE" and "absent" in n["6"][2], (n["5"], n["6"])
        git = shutil.which("git")
        if git:  # clé dans l'historique : bloquante, puis OK une fois déclarée révoquée
            g = Path(t) / "g"
            g.mkdir()
            run = lambda *c: subprocess.run([git, "-C", str(g), *c], capture_output=True, text=True)
            run("init", "-q")
            (g / "k.js").write_text("const k = '" + "sk_" + "live_" + "c3" * 12 + "';\n", encoding="utf-8")
            run("add", "."), run("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "x")
            (g / "k.js").write_text("const k = process.env.K;\n", encoding="utf-8")
            assert {x[0].split()[0]: x[1] for x in scanner(str(g))[1]}["1a"] == "RESTE À FAIRE"
            (g / "securite").mkdir()
            (g / "securite" / "cles-revoquees.txt").write_text(run("rev-parse", "HEAD").stdout, encoding="utf-8")
            assert {x[0].split()[0]: x[1] for x in scanner(str(g))[1]}["1a"] == "OK"
        p = Path(t) / "b"
        p.mkdir()
        (p / "app.js").write_text("const ok = 1;\n", encoding="utf-8")
        (p / "_headers").write_text("/*\n  Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: no-referrer\n  Permissions-Policy: camera=()\n", encoding="utf-8")
        pied = '<footer><a href="/mentions-legales">Mentions légales</a> <a href="/confidentialite">Confidentialité</a></footer>'
        (p / "index.html").write_text(f"<p>Bonjour</p>{pied}", encoding="utf-8")
        (p / "mentions-legales.html").write_text("Jean Test EI, 1 rue de la Paix 75002 Paris, SIREN 123 456 789, contact@exemple.fr, 01 23 45 67 89. "
                                                  "Directeur de la publication : Jean Test. Hébergeur : Cloudflare, Inc., 101 Townsend St, San Francisco, +1 650 319 8930." + pied, encoding="utf-8")
        (p / "confidentialite.html").write_text("Données personnelles : finalités, conservation 3 ans, droit d'accès et d'effacement, réclamation CNIL." + pied, encoding="utf-8")
        v, l = scanner(str(p), dist=str(p), ecommerce=False)
        assert v == "PASSE", [x for x in l if x[1] == "RESTE À FAIRE"]
    print("selftest OK")


if __name__ == "__main__":
    a = argparse.ArgumentParser()
    a.add_argument("src", nargs="?")
    a.add_argument("--dist")
    a.add_argument("--url")
    a.add_argument("--rapport")
    a.add_argument("--ecommerce", action="store_true", default=None)
    a.add_argument("--pas-ecommerce", dest="ecommerce", action="store_false")
    a.add_argument("--selftest", action="store_true")
    o = a.parse_args()
    if o.selftest:
        selftest(); sys.exit(0)
    if not o.src or not Path(o.src).is_dir():
        sys.exit("Dossier source introuvable")
    v, l = scanner(o.src, o.dist, o.url, o.ecommerce)
    txt = rapport(v, l, o.src)
    print(txt)
    if o.rapport:
        Path(o.rapport).parent.mkdir(parents=True, exist_ok=True)
        Path(o.rapport).write_text(txt + "\n", encoding="utf-8")
    sys.exit(1 if v == "ÉCHOUE" else 0)
