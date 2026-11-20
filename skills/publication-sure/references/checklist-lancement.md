# Checklist de lancement web (reprise complète de checklist-lancement-web, 20/11/2026)

Source : skill checklist-lancement-web du compte Claude. Dans publication-sure, le Bloc 0 est fait par l'étape 1 du SKILL.md (scan_securite.py + avant-mise-en-ligne.py).


Objectif : ne jamais publier un site, une boutique Shopify, une app ou un SaaS avec une faille, un manque légal ou un parcours d'achat cassé. Le lancement reste une décision de l'utilisateur : tu vérifies et tu prépares, tu ne publies rien.

## Règle de décision (bloquante)

NE PAS PUBLIER si l'un de ces points persiste :
- une clé ou un secret privé est exposé (code front, dépôt Git, build) ;
- un utilisateur peut lire ou modifier les données d'un autre ;
- le HTTPS manque ou est cassé ;
- la RLS (ou l'équivalent) est absente ou mal configurée sur des données privées ;
- des traceurs soumis à consentement partent avant l'accord ;
- des frais sont cachés ou trompeurs ;
- le parcours d'achat ou de paiement est défectueux.

## Méthode

1. Identifie le type de projet (site vitrine, boutique, app avec comptes, SaaS avec paiement) et ignore les contrôles qui ne s'appliquent pas, en le disant.
2. Passe les 5 blocs ci-dessous dans l'ordre. Pour chaque contrôle : statut OK / À CORRIGER / NON APPLICABLE / NON VÉRIFIABLE, avec la preuve ou le test fait.
3. Quand tu as accès au code ou à la base (Supabase, Vercel, Shopify), vérifie toi-même ; sinon, donne à l'utilisateur le test exact à faire.
4. Termine par le rapport (format en bas).

## Bloc 0 — Contrôle automatique (étape obligatoire, bloquante)

Avant le reste : le script Lighthouse + liens de ton projet (non fourni dans ce dépôt ; sinon `npx lighthouse <url>` et `npx linkinator <url> --recurse`). Il lance Lighthouse mobile et desktop sur toutes les pages (sitemap ou dist) et un test de liens. Seuils : performance, accessibilité, bonnes pratiques, SEO >= 95 en mobile ; 0 lien interne cassé (externes = avertissement). Rapport .md + JSON dans `<projet>/a_valider/controle-AAAA-MM-JJ/`, verdict PASSE / ÉCHOUE en 1re ligne. ÉCHOUE = aucune mise en ligne (le contrôleur lit le rapport). Si le script est absent (autre plateforme) : le dire et faire les mêmes mesures à la main.

## Bloc 1 — Sécurité technique

- HTTPS sur tout le domaine, HTTP redirigé, pas de contenu mixte ; HSTS seulement après validation. Test : http:// redirige.
- En-têtes de sécurité : CSP adaptée, nosniff, Referrer-Policy, protection des iframes. Test : SecurityHeaders.com.
- Secrets uniquement côté serveur (clés privées, jetons de paiement, clés API secrètes). Test : build JS et dépôt Git sans secret.
- Validation côté serveur (type, taille, champs) ; la validation front seule se contourne. Test : une requête modifiée est rejetée.
- Droits sur chaque ressource : identité ET droit d'accès à chaque objet. Test : le compte B ne lit ni ne modifie rien de A.
- Injection SQL / XSS : requêtes paramétrées, échappement du framework, jamais de HTML utilisateur brut. Test : du texte HTML s'affiche sans s'exécuter.
- CSRF et cookies : Secure, HttpOnly, SameSite, protection anti-CSRF si authentification par cookies.
- Dépendances à jour, aucune alerte critique, packages inutiles retirés.
- CORS limité aux origines nécessaires (ce n'est pas une barrière d'accès).
- Upload maîtrisé : taille, format réel, extensions, renommage, stockage isolé.
- Anti-abus : rate limiting sur connexion, e-mails et formulaires ; Turnstile ou CAPTCHA si nécessaire.
- Comptes admin : MFA, accès limités, aucun panneau interne visible.
- Mode production : pas de debug, pas de .env publié, pas de logs verbeux.
- E-mails envoyés avec le domaine : SPF, DKIM, DMARC.

## Bloc 2 — Données (Supabase ou équivalent)

- Clé publishable/anon côté navigateur seulement si RLS correcte ; clé service_role uniquement côté serveur.
- RLS activée sur toutes les tables exposées, droits inutiles retirés à anon/authenticated.
- Politiques par action (SELECT, INSERT, UPDATE, DELETE) liées à auth.uid() ; tests positifs ET négatifs avec trois profils : visiteur, utilisateur A, utilisateur B.
- Buckets Storage avec règles adaptées (un avatar public n'a pas les droits d'une facture).
- Auth : URLs de redirection autorisées, expiration des sessions, réinitialisation et déconnexion testées.
- Security Advisor : aucune alerte critique non traitée.
- Sauvegardes : options réelles vérifiées, restauration testée.
- Logs et alertes (erreurs 5xx, quotas) sans jamais journaliser mots de passe ou jetons.
- Environnements séparés (local, préproduction, production) et rollback prêt.

## Bloc 3 — Droit et confiance (France / UE, à vérifier selon l'activité)

- Mentions légales (identité, coordonnées), politique de confidentialité (données, finalités, base légale, conservation, droits, contact).
- CGU ; CGV si vente ; remboursements et droit de rétractation (fonctionnalité de rétractation en ligne depuis le 19/06/2026 pour les contrats concernés) ; médiateur de la consommation.
- Cookies : politique, bannière où refuser est aussi simple qu'accepter, aucun traceur avant accord, choix modifiable sur chaque page.
- Formulaires : information à la collecte, cases décochées, minimisation des données, durées de purge.
- Inventaire des outils tiers (analytics, pixels, chat, CAPTCHA, IA) et des transferts hors UE.
- Aucun dark pattern, aucune fausse urgence, aucun frais caché (TTC, livraison, abonnement affichés avant paiement).
- Aucun faux avis, aucune promesse ou chiffre non démontrable.
- Licences des images, icônes, vidéos, polices.
- Mineurs : en France, consentement conjoint sous 15 ans si le traitement repose sur le consentement.
- Lien de désinscription fonctionnel dans les e-mails promotionnels ; procédure de suppression de compte.
- Procédure de fuite de données (notification CNIL sous 72 h si risque).

## Bloc 4 — UX, SEO et conversion

- Un CTA principal clair, utilisable au pouce sur mobile.
- Title unique et méta-description utile par page ; og:image testée ; favicon.
- sitemap.xml, robots.txt, canonical, noindex des pages privées ; Search Console.
- Page 404 personnalisée qui renvoie bien le statut 404 ; liens cassés vérifiés.
- FAQ sur les vraies objections ; délais promis tenables ; page de remerciement après action.
- Accessibilité : contraste, navigation au clavier, focus visible, textes alternatifs, zoom 200 %.
- Performance : LCP ≤ 2,5 s, INP ≤ 200 ms, CLS ≤ 0,1 (PageSpeed mobile et desktop) ; images compressées.

## Bloc 5 — Tests réels avant publication

- Formulaires : vide, invalide, trop long, erreur serveur, double clic, succès, réception, mobile.
- Achat en mode test puis remboursement ; TTC, total, facture corrects.
- E-mails réellement reçus (inscription, réinitialisation, facture, support).
- Webhooks : signature vérifiée, répétition sans doublon.
- Navigation privée : aucun traceur déposé avant accord.
- Domaine et DNS protégés par MFA ; retour à la version stable possible.

## Format du rapport

1. Verdict en une ligne : PRÊT À PUBLIER / À CORRIGER AVANT PUBLICATION / BLOQUÉ (point bloquant cité).
2. Points bloquants, puis points à corriger classés par gravité, chacun avec la correction exacte et où la faire.
3. Points non vérifiables et le test que l'utilisateur doit faire.
4. Rappel : l'utilisateur publie lui-même. Pour le juridique, ce contrôle ne remplace pas un professionnel.
