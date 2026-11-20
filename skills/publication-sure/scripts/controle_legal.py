"""Contrôle légal FR/UE d'un site (repérage automatique sur le HTML, pas un avis juridique). Aucune dépendance.
Usage : python controle_legal.py <dossier build> [--ecommerce | --pas-ecommerce] [--rapport f.md]
        python controle_legal.py --selftest
Couvre : mentions légales LCEN (art. 1-1 et 19), confidentialité RGPD, cookies et traceurs (CNIL), formulaires,
et pour un site marchand : CGV, rétractation 14 jours, bouton « renoncer au contrat ici » (L221-21 et D221-5,
depuis le 19/06/2026), formulaire type, médiateur de la consommation (R616-1), prix TTC et livraison, ancien lien RLL/ODR.
Sources vérifiées le 20/11/2026 : entreprendre.service-public.gouv.fr F37351 et F23455, Légifrance L221-21, francenum.gouv.fr.
"""
import argparse, html, re, sys, tempfile
from pathlib import Path

TRACEURS = {"Google Analytics": r"google-analytics\.com|googletagmanager\.com/gtag|\bgtag\(", "Google Tag Manager": r"googletagmanager\.com/gtm",
            "Meta Pixel": r"connect\.facebook\.net|\bfbq\(", "TikTok Pixel": r"analytics\.tiktok\.com", "Hotjar": r"static\.hotjar\.com",
            "Microsoft Clarity": r"clarity\.ms", "LinkedIn Insight": r"snap\.licdn\.com", "Pinterest Tag": r"\bpintrk\(", "Snap Pixel": r"sc-static\.net",
            "YouTube intégré (cookies)": r"youtube\.com/embed", "Google Maps intégré": r"google\.com/maps/embed"}
CMP = r"tarteaucitron|axeptio|cookiebot|didomi|onetrust|klaro|orejime|cookieconsent|iubenda|complianz|consentmanager|usercentrics"
# signaux forts seulement : un lien « Acheter le jeu » d'un guide n'est pas une boutique
MARCHAND = r"ajouter au panier|add to cart|(votre|mon) panier|checkout|cdn\.shopify|lemonsqueezy|paddle\.com|passer (la|ma) commande"
PAIEMENT = r"js\.stripe\.com|buy\.stripe\.com|paypal\.com/sdk|helloasso"
DON = r"faire un don|\bdons?\b|donate|donation|soutenir l.association|helloasso"


def _texte(h):
    h = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", h)
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", h)))


def _actifs(h):
    """HTML sans les scripts mis en attente de consentement (type=text/plain), qui ne partent pas avant l'accord."""
    return re.sub(r"(?is)<script\b[^>]*type=[\"']text/plain[\"'][^>]*>.*?</script>", " ", h)


def _page(pages, motif):
    for chemin, h in pages.items():
        if re.search(motif, chemin, re.I):
            return chemin, h
    for chemin, h in pages.items():  # sinon, la page liée par un lien qui porte ce nom
        for href, txt in re.findall(r"(?is)<a\b[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", h):
            if re.search(motif, _texte(txt), re.I):
                cle = href.strip("/").split("?")[0].split("#")[0]
                for c2, h2 in pages.items():
                    if cle and c2.rstrip("/").removesuffix(".html").endswith(cle.removesuffix(".html")):
                        return c2, h2
    return None, ""


def controler(pages, ecommerce=None):
    """pages = {chemin ou url: html}. Renvoie des lignes (point, statut, info, détails, correction)."""
    L = []
    tout = " ".join(pages.values())
    texte = _texte(tout)
    paiement, don = re.search(PAIEMENT, tout, re.I), re.search(DON, texte, re.I)
    dons = ecommerce is None and paiement and don and not re.search(MARCHAND, tout, re.I)  # paiement pour des dons, pas une boutique
    marchand = bool(re.search(MARCHAND, tout, re.I) or (paiement and not dons)) if ecommerce is None else ecommerce

    # mentions légales
    ch, h = _page(pages, r"mentions[-_ ]?l[ée]gales|legal|impressum")
    t = _texte(h)
    elements = {"nom + EI, forme de société (SAS, SARL...) ou association": r"\bEI\b|entrepreneur individuel|\bSASU?\b|\bSARL\b|\bEURL\b|\bSA\b|\bSCI\b|association",
                "SIREN / SIRET / RCS / RNE (association : RNA)": r"(SIREN|SIRET|RCS|RNE)\D{0,25}\d{3}\s?\d{3}\s?\d{3}|\bW\d{9}\b",
                "adresse postale": r"\b\d{5}\s+[A-ZÀ-Ü]", "e-mail": r"[\w.+-]+@[\w-]+\.\w+|mailto:", "téléphone": r"(\+33\s?|0)[1-9](?:[\s.-]?\d{2}){4}|\+\d[\d\s]{8,}",
                "hébergeur (nom, adresse, téléphone)": r"h[ée]berg", "directeur de la publication": r"(directeur|responsable)\s+de\s+(la\s+)?publication"}
    manque = [n for n, m in elements.items() if not re.search(m, t if ch else "", re.I)]
    anonyme = ch and re.search(r"anonymat", t, re.I) and re.search(r"h[ée]berg", t, re.I)  # LCEN 1-1 III : particulier non professionnel
    L.append(("L1 Mentions légales (LCEN)", ("À VÉRIFIER" if anonyme and not marchand else "RESTE À FAIRE") if manque else "OK",
              f"page {ch} : éditeur anonyme, permis seulement à un particulier sans activité professionnelle (pub, affiliation, vente = identité complète)" if anonyme and manque else
 f"page {ch}" + (" incomplète" if manque else " complète") if ch else "aucune page de mentions légales",
              manque if ch else list(elements), "page « Mentions légales » : nom prénom + EI, adresse, e-mail, téléphone, SIREN, directeur de publication, hébergeur (nom, adresse, téléphone) ; amende jusqu'à 75 000 EUR pour une EI"))
    sans = [c for c, x in pages.items() if not re.search(r"mentions[-_ ]?l[ée]gales|legal", x, re.I)]
    if ch and sans:
        L.append(("L1b Lien permanent vers les mentions", "RESTE À FAIRE", f"{len(sans)} page(s) sans lien (accès « facile, direct et permanent »)", sans[:8], "mettre le lien Mentions légales dans le pied de page commun"))

    # confidentialité RGPD
    collecte = re.search(r"(?i)<input\b[^>]*type=[\"']?(email|tel)|<textarea|name=[\"']?(email|nom|name|phone)", tout)
    trac = sorted({n for n, m in TRACEURS.items() if re.search(m, _actifs(tout), re.I)})
    ch2, h2 = _page(pages, r"confidentialit|privacy|donn[ée]es[-_ ]personnelles|rgpd")
    t2 = _texte(h2)
    attendus = {"finalités": r"finalit|pourquoi|utilis", "durée de conservation": r"conserv", "droits (accès, effacement...)": r"droit d.acc[eè]s|effacement|rectification|opposition",
                "recours CNIL": r"\bCNIL\b"}
    manque2 = [n for n, m in attendus.items() if not re.search(m, t2, re.I)]
    besoin = bool(collecte or trac or marchand)
    st = "RESTE À FAIRE" if (not ch2 and besoin) or (ch2 and manque2) else ("À VÉRIFIER" if not ch2 else "OK")
    L.append(("L2 Politique de confidentialité (RGPD)", st, (f"page {ch2}" + (" incomplète" if manque2 else " complète")) if ch2 else ("absente alors que le site collecte des données" if besoin else "absente (site sans formulaire ni traceur repéré)"),
              manque2 if ch2 else [], "page « Confidentialité » : données collectées, finalités, base légale, durée de conservation, destinataires et transferts hors UE, droits et contact, recours CNIL"))

    # cookies et traceurs
    cmp = re.search(CMP, tout, re.I)
    refus = re.search(r"tout refuser|refuser|continuer sans accepter|rejeter", texte, re.I)
    if trac and not cmp and not refus:
        L.append(("L3 Cookies et traceurs (CNIL)", "RESTE À FAIRE", "traceurs chargés sans bandeau de consentement", trac,
                  "bloquer ces scripts jusqu'à l'accord (bandeau gratuit : tarteaucitron ou Orejime) avec « Tout refuser » aussi visible que « Tout accepter », choix modifiable sur chaque page ; ou passer à une mesure d'audience exemptée (Plausible, Matomo réglé, Cloudflare Web Analytics)"))
    elif trac:
        L.append(("L3 Cookies et traceurs (CNIL)", "À VÉRIFIER", "bandeau repéré", trac, "F12 > Réseau, cache vidé : aucune requête vers ces traceurs avant le clic sur Accepter ; Refuser aussi simple qu'Accepter"))
    else:
        L.append(("L3 Cookies et traceurs (CNIL)", "OK", "aucun traceur soumis à consentement repéré dans le HTML", [], ""))

    # formulaires
    coche = re.findall(r"(?i)<input\b[^>]*type=[\"']?checkbox[^>]*\bchecked\b[^>]*>", tout)
    info_f = re.search(r"donn[ée]es|confidentialit|RGPD", texte, re.I)
    pb_f = (["case pré-cochée (consentement non valable)"] if coche else []) + (["pas d'information sur l'usage des données près du formulaire"] if collecte and not info_f else [])
    L.append(("L4 Formulaires", "RESTE À FAIRE" if pb_f else ("OK" if collecte else "NON APPLICABLE"), "formulaire à corriger" if pb_f else ("formulaire avec information" if collecte else "aucun formulaire de données"), pb_f,
              "cases décochées par défaut ; phrase sous le formulaire : qui traite, pourquoi, lien vers Confidentialité"))

    # site marchand
    if dons:
        L.append(("L5 Dons en ligne", "À VÉRIFIER", "paiement pour des dons repéré, pas de boutique (forcer avec --ecommerce si des biens ou services sont vendus)", [],
                  "page de don : qui reçoit (association, n° RNA), usage des fonds, reçu fiscal seulement si l'association y a droit (intérêt général, à vérifier), paiement sur une page sécurisée du prestataire"))
        return L
    if not marchand:
        L.append(("L5 Vente en ligne", "NON APPLICABLE", "aucun panier, paiement ni bouton d'achat repéré (forcer avec --ecommerce)", [], ""))
        return L
    chc, hc = _page(pages, r"\bcgv\b|conditions[-_ ]g[ée]n[ée]rales[-_ ]de[-_ ]vente")
    tc = _texte(hc)  # le délai se lit dans les CGV, pas n'importe où sur le site
    delais = [int(x) for x in re.findall(r"(?i)r[ée]tractation\D{0,80}?(\d{1,2})\s*jours", tc)]
    obl = {"page CGV": bool(chc),
           "droit de rétractation de 14 jours dans les CGV": bool(re.search(r"r[ée]tractation", tc, re.I) and re.search(r"14 jours|quatorze jours", tc, re.I) and not any(x < 14 for x in delais)),
           "bouton « renoncer au contrat ici » (obligatoire depuis le 19/06/2026)": bool(re.search(r"renoncer au contrat", texte, re.I)),
           "formulaire type de rétractation": bool(re.search(r"formulaire (type )?de r[ée]tractation", texte, re.I)),
           "médiateur de la consommation (nom + site)": bool(re.search(r"m[ée]diat(eur|ion) de la consommation", texte, re.I)),
           "prix TTC ou « TVA non applicable, art. 293 B du CGI »": bool(re.search(r"\bTTC\b|toutes taxes|293 B", texte, re.I)),
           "frais et délais de livraison": bool(re.search(r"livraison|frais de port|exp[ée]dition", texte, re.I))}
    manque5 = [n for n, ok in obl.items() if not ok]
    manque5 += [f"délai de rétractation de {x} jours dans les CGV (14 minimum)" for x in sorted(set(delais)) if x < 14]
    ht = re.findall(r"\d[\d\s]*(?:[,.]\d{2})?\s?(?:€|EUR)\s*HT\b", texte)  # vente aux particuliers : prix affichés TTC
    manque5 += [f"prix affiché HT : {x.strip()}" for x in ht[:3]]
    L.append(("L5 Vente en ligne (code de la consommation)", "RESTE À FAIRE" if manque5 else "OK", "obligations marchandes manquantes" if manque5 else "CGV, rétractation, bouton, médiateur, prix présents", manque5,
              "CGV avec rétractation 14 jours et formulaire type ; lien ou bouton « renoncer au contrat ici » visible pendant 14 jours qui mène à « confirmer la rétractation » et envoie un accusé de réception ; médiateur nommé avec son site ; prix TTC et livraison avant paiement"))
    if re.search(r"ec\.europa\.eu/consumers/odr", tout, re.I):
        L.append(("L5b Ancien lien RLL/ODR", "RESTE À FAIRE", "lien vers la plateforme européenne fermée le 20/07/2025 (lien mort, information fausse)", [], "retirer le lien ; garder le médiateur"))
    L.append(("L5c Bouton de commande", "À VÉRIFIER" if not re.search(r"obligation de paiement|payer", texte, re.I) else "OK",
              "aucun « commande avec obligation de paiement » ou « payer » repéré (souvent sur la page de paiement externe)", [], "le dernier bouton dit « Commande avec obligation de paiement » ou « Payer » (L221-14)"))
    return L


def selftest():
    pied = '<footer><a href="/mentions-legales">Mentions légales</a> <a href="/confidentialite">Confidentialité</a></footer>'
    mauvais = {"index.html": '<script src="https://www.googletagmanager.com/gtag/js?id=G-X"></script><button>Ajouter au panier</button>'
                             '<form><input type="email" name="email"><input type="checkbox" checked></form>'}
    l = {x[0].split()[0]: x for x in controler(mauvais)}
    assert l["L1"][1] == l["L2"][1] == l["L3"][1] == l["L4"][1] == l["L5"][1] == "RESTE À FAIRE", l
    assert any("renoncer" in d for d in l["L5"][3]), l["L5"]
    bloque = {"index.html": '<script type="text/plain" data-category="analytics" src="https://www.googletagmanager.com/gtag/js"></script><p>x</p>'}
    assert {x[0].split()[0]: x[1] for x in controler(bloque, False)}["L3"] == "OK"
    bon = {"index.html": "<p>Boutique</p><button>Ajouter au panier</button>" + pied,
           "mentions-legales.html": "Jean Test EI, 1 rue X 75002 Paris, SIREN 123 456 789, a@b.fr, 01 23 45 67 89, directeur de la publication Jean Test, hébergeur Cloudflare" + pied,
           "confidentialite.html": "finalités, conservation, droit d'accès, CNIL" + pied,
           "cgv.html": "Droit de rétractation de 14 jours, formulaire type de rétractation, renoncer au contrat ici, médiateur de la consommation CM2C, prix TTC, livraison 5 EUR, Payer" + pied}
    l = controler(bon)
    assert not [x for x in l if x[1] == "RESTE À FAIRE"], l
    # cas du banc (20/11) : « 14 jours » et « TTC » ailleurs sur le site ne couvrent pas des CGV à 7 jours ni un prix HT
    faux = {**bon, "index.html": "<p>Remboursement sous 14 jours. Total TTC au panier.</p><p>Bougie 24,00 € HT</p><button>Ajouter au panier</button>" + pied,
            "cgv.html": bon["cgv.html"].replace("Droit de rétractation de 14 jours", "Droit de rétractation : 7 jours")}
    l5 = {x[0].split()[0]: x for x in controler(faux)}["L5"]
    assert l5[1] == "RESTE À FAIRE" and any("7 jours" in d for d in l5[3]) and any("HT" in d for d in l5[3]), l5
    # association : RNA au lieu du SIREN, paiement Stripe pour des dons = pas une boutique
    asso = {"index.html": '<script src="https://js.stripe.com/v3"></script><p>Faire un don</p>' + pied,
            "mentions-legales.html": "Association Les Amis, W751234567, 1 rue X 75002 Paris, a@b.fr, 01 23 45 67 89, directeur de la publication Jean Test, hébergeur Cloudflare" + pied,
            "confidentialite.html": bon["confidentialite.html"]}
    l = {x[0].split()[0]: x for x in controler(asso)}
    assert l["L1"][1] == "OK" and l["L5"][1] == "À VÉRIFIER" and "Dons" in l["L5"][0], (l["L1"], l["L5"])
    print("selftest légal OK")


if __name__ == "__main__":
    a = argparse.ArgumentParser()
    a.add_argument("dist", nargs="?")
    a.add_argument("--ecommerce", action="store_true", default=None)
    a.add_argument("--pas-ecommerce", dest="ecommerce", action="store_false")
    a.add_argument("--rapport")
    a.add_argument("--selftest", action="store_true")
    o = a.parse_args()
    if o.selftest:
        selftest(); sys.exit(0)
    if not o.dist or not Path(o.dist).is_dir():
        sys.exit("Dossier build introuvable")
    pages = {p.relative_to(o.dist).as_posix(): p.read_text(encoding="utf-8", errors="ignore") for p in Path(o.dist).rglob("*.html")}
    L = controler(pages, o.ecommerce)
    v = "ÉCHOUE" if any(x[1] == "RESTE À FAIRE" for x in L) else "PASSE"
    txt = "\n".join([f"Verdict légal : {v}", "", "| Point | Statut | Détail | Correction |", "|---|---|---|---|"] +
                    [f"| {n} | {s} | {i}{' : ' + '; '.join(d[:8]) if d else ''} | {c if s not in ('OK', 'NON APPLICABLE') else ''} |" for n, s, i, d, c in L])
    print(txt)
    if o.rapport:
        Path(o.rapport).parent.mkdir(parents=True, exist_ok=True)
        Path(o.rapport).write_text(txt + "\n", encoding="utf-8")
    sys.exit(1 if v == "ÉCHOUE" else 0)
