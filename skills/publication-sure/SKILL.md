---
name: publication-sure
description: "Porte unique avant de mettre en ligne un site, une boutique, une app, une API ou un SaaS - teste vraiment la sécurité (clés secrètes dans le code, le build, le JS servi, les source maps et l'historique git, .env et .git exposés, paquets inventés et npm audit, en-têtes, cookies, CORS, sondes locales type ZAP : XSS, traces d'erreur, admin ouvert, limite de tentatives), contrôle le légal FR/UE (mentions légales, RGPD, cookies, CGV, rétractation et bouton « renoncer au contrat ici », médiateur), lance le contrôle automatique Lighthouse et liens, passe la checklist de lancement (sécurité, RGPD, vente, SEO), l'audit SEO des pages, et dit quand un pentest Strix ou un audit security-audit complet s'impose. Rend un verdict PASSE ou ÉCHOUE avec rapport. À utiliser dès qu'on parle de publier, mettre en ligne, déployer, lancer, « je peux poster le site ? », « teste la sécurité », « audit avant publication », pentest, faille, contrôle SEO avant lancement, nouvelle version publique, même si aucun de ces mots n'est exact."
---

# Publication sûre

Un seul nom pour la porte de sortie d'un site ou d'une app. Il fait tourner les contrôles qui existent vraiment, dit ce qui n'a pas pu être testé, et bloque la mise en ligne tant qu'un point reste ouvert.
Appelés, jamais recopiés : security-audit, les skills Strix, seo-page-audit. Le détail de la checklist est dans `references/checklist-lancement.md` (reprise complète de checklist-lancement-web).

## 0. Avant de commencer
- Écris `Terminé = verdict écrit (PRÊT À PUBLIER / À CORRIGER AVANT PUBLICATION / BLOQUÉ) dans <projet>/a_valider/controle-AAAA-MM-JJ/VERDICT.md, chaque point avec sa preuve`. Un BLOQUÉ justifié est une fin correcte du contrôle (le contrôle est fini, pas la publication) ; PRÊT exige PASSE aux étapes 1 et 2 et aucun RESTE À FAIRE.
- Les rapports vont dans `a_valider/` et `securite/`, que le scan ignore (pas d'auto-contamination au 2e passage).
- Cible : la source (dossier du code), le build (`dist`, `build`, `out`) et, s'il est en ligne, l'URL. Préfère la préproduction à la production.
- On ne teste que ce qui appartient à l'utilisateur ou ce qu'il est autorisé à tester.

## 1. Contrôles automatiques (bloquants)
1. Sécurité et légal, une commande : `python <skill>/scripts/scan_securite.py <source> --dist <build> [--ecommerce] --rapport <projet>/a_valider/controle-AAAA-MM-JJ/securite.md`
   Serveur de dev déjà lancé (app avec API) : `--url http://127.0.0.1:<port>/` à la place de `--dist`. Code 1 = ÉCHOUE. Chaque ligne non OK porte sa correction.
   - Statique (source + build + git) : clés secrètes (Stripe, AWS, GitHub, OpenAI, Anthropic, Resend, SendGrid, Shopify, clés privées, JWT Supabase `service_role` décodé), historique git du projet, `.env` publiés ou suivis, source maps et `.git` dans le build, paquets inventés + `npm audit` (critique ou élevée = bloquant), webhooks sans signature.
   - Sondes en local, esprit OWASP ZAP baseline (`scripts/sondes_site.py`, le build est servi comme par l'hébergeur, `_headers` appliqué) : en-têtes (CSP, nosniff, Referrer-Policy, anti-iframe, Permissions-Policy, version du serveur), cookies (Secure, HttpOnly, SameSite), CORS (origine étrangère renvoyée), fichiers exposés (`.env`, `.git`, dumps, sauvegardes), secrets et source maps dans le JS servi (ce que montre F12), traces d'erreur, XSS réfléchi, routes admin ouvertes, limite de tentatives (30 POST rapides, 429 attendu).
   - Légal FR/UE (`scripts/controle_legal.py`) : mentions légales LCEN, lien permanent, confidentialité RGPD, traceurs sans bandeau (CNIL), cases pré-cochées ; site marchand (auto ou `--ecommerce`) : CGV, rétractation 14 jours, bouton « renoncer au contrat ici » (depuis le 19/06/2026), formulaire type, médiateur, prix TTC et livraison, ancien lien RLL/ODR.
   - Reste À VÉRIFIER à la main : RLS (commande curl donnée), parcours de commande, bandeau qui bloque vraiment avant accord (F12 > Réseau).
   - Ce que le script ne sait pas trancher seul : clé fuitée dans un ancien commit et déjà révoquée -> écrire le commit dans `<source>/securite/cles-revoquees.txt` (le point redevient OK) ; site qui reçoit des dons (association, RNA) -> détecté comme « Dons », pas comme boutique ; vente aux seuls professionnels (prix HT permis) -> `--pas-ecommerce` et l'écrire dans l'audit.
   Garde-fous : sondes refusées hors localhost ; une `--url` distante ne fait qu'une requête d'en-têtes, comme un visiteur. ZAP et Strix : non utilisés (pas de Java ni Docker sur le PC ; Strix désactivé par l'utilisateur).
   Autotests : `python <skill>/scripts/scan_securite.py --selftest` (idem `sondes_site.py`, `controle_legal.py`).
2. Qualité : le script Lighthouse + liens de ton projet (non fourni dans ce dépôt) ou : `npx lighthouse <url> --blocked-url-patterns=<tiers>` et `npx linkinator <url> --recurse --skip "^https?://(?!<hôte>)"`). Lighthouse mobile et ordinateur, seuil 95 partout en mobile, 0 lien interne cassé. Liens externes jamais contactés par défaut (`--externes` pour les tester, seulement si l'utilisateur le veut) ; scripts tiers (analytics, Stripe) bloqués avec `--bloquer` pour mesurer le vrai dist sans contacter le tiers. Verdict PASSE / ÉCHOUE en 1re ligne de `a_valider/controle-AAAA-MM-JJ/rapport.md`.
   Un outil qui plante (npx hors ligne, Chrome absent) : statut NON VÉRIFIABLE avec le message d'erreur dans VERDICT.md, jamais OK ; le verdict ne peut pas être PRÊT tant qu'il n'a pas tourné.
Chaque « À VÉRIFIER » devient un test manuel fait et écrit (étape 3), pas une case ignorée.

## 2. Selon le projet
| Le projet a... | Lancer | Pourquoi |
|---|---|---|
| Du code serveur, une API, des comptes, un paiement | security-audit en mode « audit complet » | Revue de la source sans réseau, failles réelles avec correctifs |
| Un petit projet (moins de 20 fichiers de code serveur, une seule route sensible) | security-audit en revue ciblée sur ces fichiers (auth, paiement, formulaires), pas l'audit complet | Proportion : l'audit complet d'un petit projet coûte sans rien trouver de plus ; écrire la liste des fichiers relus |
| Des comptes, un paiement ou des données privées, ET Docker + clé d'un modèle (ou compte Strix) | web-app-penetration-testing (site en ligne), api-security-testing (API), find-security-vulnerabilities-in-code (dépôt) ; entrée générale : penetration-testing-with-strix | Attaque réelle qui prouve la faille ; deux comptes de test pour l'accès entre utilisateurs |
| Des failles Strix trouvées | fix-security-vulnerabilities-with-strix | Corriger la cause, relancer Strix pour prouver |
| Des pages publiques | seo-page-audit sur chaque page qui compte | Titre, description, structure, données ; corrections avant la mise en ligne |
| Une base Supabase | Test RLS de la checklist (bloc 2) | Clé anon sans session : rien de privé ne sort |
Strix demande Docker et une clé de modèle (ou un compte app.strix.ai) : créer un compte, saisir une clé ou payer des crédits reste à l'utilisateur. Sans eux, le dire et s'appuyer sur security-audit + le scan.
Site vitrine statique sans formulaire ni compte : les étapes 1 et 3 suffisent, Strix est disproportionné.

## 3. Checklist de lancement (manuel, avec preuves)
Charge `references/checklist-lancement.md` et passe les blocs utiles (1 sécurité, 2 données, 3 droit et confiance, 4 UX/SEO/conversion, 5 tests réels). Statut par contrôle : OK / À CORRIGER / NON APPLICABLE / NON VÉRIFIABLE, avec la preuve ou le test fait. Résultat de l'audit dans `<projet>/securite/audit-AAAA-MM-JJ.md` : une ligne par faille, OK / CORRIGÉ / NON APPLICABLE (raison) / RESTE À FAIRE.

## 4. Verdict et rapport
Où est quoi (`<projet>/a_valider/controle-AAAA-MM-JJ/`) :
| Fichier | Écrit par | Statuts |
|---|---|---|
| `securite.md` | scan_securite.py (étape 1) | PASSE / ÉCHOUE ; lignes OK, NON APPLICABLE, À VÉRIFIER, RESTE À FAIRE |
| `rapport.md` | avant-mise-en-ligne.py (étape 2) | PASSE / ÉCHOUE |
| `<projet>/securite/audit-AAAA-MM-JJ.md` | toi (étape 3) | OK / CORRIGÉ / NON APPLICABLE (raison) / RESTE À FAIRE |
| `VERDICT.md` | toi (étape 4) | PRÊT À PUBLIER / À CORRIGER AVANT PUBLICATION / BLOQUÉ |
Correspondance : un ÉCHOUE ou un RESTE À FAIRE = au mieux À CORRIGER ; une clé ou un mot de passe exposé, un admin ouvert, une RLS ouverte = BLOQUÉ ; PRÊT seulement avec deux PASSE et chaque À VÉRIFIER testé et écrit.
1. Une ligne : PRÊT À PUBLIER / À CORRIGER AVANT PUBLICATION / BLOQUÉ (point cité). Puis, pour un lecteur non technique, une phrase sur ce que ça veut dire (« pas en ligne demain tel quel : 2 corrections d'une heure »).
2. Points bloquants, puis à corriger par gravité, chacun avec la correction et où la faire.
3. Ce qui n'a pas pu être testé (Strix sans Docker, site hors ligne, pas de compte de test) et le test exact à faire.
4. Dans l'AIOS : le contrôleur lit les rapports ; publication permise après son GO selon la règle d'autonomie du projet. Ailleurs : l'utilisateur publie lui-même.
Le juridique (RGPD, CGV, mentions) : les faits et quand consulter un professionnel, jamais un avis définitif.

## Interdits
- Publier avec un ÉCHOUE ou un RESTE À FAIRE.
- Afficher, copier ou stocker une clé trouvée : fichier et ligne seulement, et dire de la révoquer.
- Lancer Strix ou une attaque sur un site qui n'est pas à l'utilisateur, ou sur la production sans accord. Les sondes ne visent que localhost (rafales de POST = écritures dans l'app testée : jamais sur une vraie base).
- Créer un compte, saisir une clé, acheter des crédits.
