# Changelog publication-sure

## 2.1.0 (2026-11-20, corrections après le banc : 5 cas joués, moyenne 8,3)
- sondes_site.py : un POST par formulaire avant le contrôle des cookies (le Set-Cookie de connexion était invisible en GET) ; formulaires GET suivis pour le XSS réfléchi avec leurs vrais noms de champs ; formulaire POST qui répond 404/405/501 = S10b À VÉRIFIER (était classé NON APPLICABLE) ; correction d'en-têtes aussi pour un serveur applicatif (helmet, nginx). Test : app piégée (cookie au POST, /recherche?q= non échappé) : avant S2 OK et S8 OK, après RESTE À FAIRE.
- scan_securite.py : mot de passe en dur par nom de variable sans seuil de longueur (1f, i18n et tests exclus) ; a_valider/ et securite/ ignorés (fin de l'auto-contamination « webhook ») ; mots trouvés seulement dans des .md ne déclenchent plus webhooks/RLS ; lockfile absent = RESTE À FAIRE + chaque paquet demandé au registre (`npm view`) ; clé révoquée déclarée dans securite/cles-revoquees.txt (PASSE de nouveau atteignable) ; doublon source/build supprimé. Autotest étendu (git réel). Vrais projets : une app PASSE, un site PASSE, aucun nouveau faux bloquant (2 faux positifs du nouveau motif corrigés avant livraison).
- controle_legal.py : délai de rétractation lu dans les CGV seulement (7 jours = bloquant), prix « HT » affiché = bloquant, lien ODR périmé = RESTE À FAIRE, association : RNA accepté et paiement pour des dons = ligne « Dons » au lieu des obligations de boutique. Test : cas « 14 jours et TTC ailleurs, CGV à 7 jours, prix HT » : avant L5 OK, après RESTE À FAIRE.
- avant-mise-en-ligne.py (AIOS) : liens externes jamais contactés par défaut (`--externes` pour les tester), `--bloquer` pour bloquer les scripts tiers pendant Lighthouse. Test : site à un lien externe : défaut 0 lien externe contacté, `--externes` 1.
- SKILL.md : Terminé atteignable avec un BLOQUÉ justifié, table fichiers de rapport et statuts, profil léger de security-audit, outil en panne = NON VÉRIFIABLE, cas clé révoquée, dons, vente B2B.

## 2.0.0 (2026-11-20)
- Demande de l'utilisateur : « un vrai script de sécurité qui contrôle vraiment tout », « que tout soit bien caché » (F12), « qu'il teste de hacker le site », « tout ce qu'il faut mettre dans son site web pour qu'il soit légal ». Outils gratuits et locaux seulement ; Strix reste désactivé.
- scan_securite.py devient le point d'entrée unique (statique + sondes + légal, une ligne de correction par point) : nouvelles clés (Resend, SendGrid, Shopify, compte de service Google), JWT Supabase décodé (role service_role = bloquant), historique git du projet, source maps et .git dans le build, valeurs de type secret à lire, npm audit élevé = bloquant.
- Nouveau scripts/sondes_site.py (esprit OWASP ZAP baseline, localhost seulement) : sert le build comme l'hébergeur (_headers, /page -> page.html, 404), en-têtes, cookies, CORS, fichiers exposés, secrets et source maps du JS servi, traces d'erreur, XSS réfléchi, routes admin, limite de tentatives.
- Nouveau scripts/controle_legal.py : LCEN, RGPD, CNIL cookies, formulaires, vente en ligne (rétractation, « renoncer au contrat ici » depuis le 19/06/2026, médiateur, RLL/ODR fermée le 20/07/2025). Sources vérifiées le 20/11/2026 (service-public.gouv.fr F37351 et F23455, Légifrance L221-21, francenum.gouv.fr).
- ZAP non intégré : Java 11+ absent du PC (ni Docker). Sondes maison à la place.
- Essais : site factice piégé (14 bloquants statiques, 9 failles dynamiques sur 9 trouvées), un vrai site PASSE (2 À VÉRIFIER justes), une vraie app PASSE sans faux positif.

## 1.0.0 (2026-11-20)
- Création par le CTO (super-skills, demande de l'utilisateur du 20/11) : regroupe checklist-lancement-web (copiée en entier dans references/), la règle AUDIT-AVANT-PUBLICATION, avant-mise-en-ligne.py, et le point d'entrée vers security-audit, Strix (web, API, code, correction) et seo-page-audit.
- Nouveau : scripts/scan_securite.py (sans dépendance) : clés secrètes source + build (valeur jamais affichée), .env, paquets npm + npm audit, en-têtes, HTTPS ; signale RLS, admin, formulaires, webhooks à vérifier ; --selftest.
- Essais : un vrai site (source + dist) PASSE ; une vraie app : PASSE avec 5 points À VÉRIFIER (Supabase, routes, API, webhook de paiement, mots secrets côté serveur).

