# EGEV ONE SUITE 2.0 : installation de TEST

**Statut : contrôles locaux réussis, validation Supabase réelle et recette métier encore nécessaires. Ne pas remplacer directement le site en production.**

Cette version remplace le simple verrouillage JavaScript par un serveur Node.js. Les trois outils sont conservés dans `private/tools`, jamais dans le répertoire public. Le serveur vérifie la session Supabase, le compte actif, le rôle et les modules avant de transmettre un fichier. GitHub Pages seul ne peut pas exécuter ce serveur.

## 1. Préparer sans toucher à l’existant

- Conserver une copie de votre site actuel.
- Créer un NOUVEAU projet Supabase de test, distinct de FIELD/ADMIN. Les scripts ne modifient aucune table FIELD/ADMIN, mais un projet distinct évite toute interférence avec les réglages Auth existants.
- Créer un dépôt GitHub PRIVÉ. Y déposer le contenu du package, avec `server.mjs` et `package.json` à la racine. Ne jamais publier les outils ou le ZIP dans un dépôt public.
- Ne jamais déposer de fichier `.env` contenant de vraies clés. `.env.example` ne contient que des emplacements à remplacer.

## 2. Préparer Supabase

1. Exécuter `sql/01_installation.sql` dans SQL Editor.
2. Exécuter `sql/03_verifications.sql`. Résultats attendus indiqués dans le fichier.
3. Désactiver les inscriptions publiques dans Auth. L’accès se fait uniquement sur invitation.
4. Activer la méthode e-mail/mot de passe et TOTP MFA. Régler la longueur minimale des nouveaux mots de passe à 14 caractères.
5. Configurer un SMTP adapté à l’envoi vers les destinataires de test. La réception effective des e-mails n’a pas été testée ici.
6. Copier l’URL du projet, la clé publishable et la clé secret depuis les réglages API Keys. Une ancienne clé anon/service_role est également prise en charge, mais les nouvelles clés sont préférables.

## 3. Héberger le serveur

Exemple : un Web Service Node sur Render connecté au dépôt privé.

- Version Node : 24, définie dans `package.json`.
- Build command : `node --check server.mjs`
- Start command : `node server.mjs`
- Health check : `/healthz`
- Une seule instance serveur, sans autoscaling ni CDN mettant en cache les réponses.
- Variables d’environnement : reprendre les noms de `.env.example` dans les réglages du service.
- `NODE_ENV=production`.
- `SITE_ORIGIN` = l’adresse HTTPS exacte du service, sans slash final ni chemin.
- `SUPABASE_URL` = l’adresse HTTPS du projet Supabase.
- `SUPABASE_PUBLISHABLE_KEY` et `SUPABASE_SECRET_KEY` = les clés correspondantes, uniquement dans les variables du serveur.
- Le port est fourni par l’hébergeur ; à défaut, le serveur utilise 3000.

Un Dockerfile est aussi fourni. Sa construction et son déploiement Docker n’ont pas été exécutés dans cet environnement.

**Ne pas activer GitHub Pages pour ce dépôt et ne pas déplacer les fichiers `private/tools` dans `public`.**

## 4. Configurer les liens e-mail

Dans Supabase Auth, URL Configuration :

- Site URL = la même origine HTTPS que `SITE_ORIGIN`, sans slash final.
- Redirect URLs : ajouter l’adresse du site suivie de `/activate`.

Dans Email Templates :

- Invite user : copier le contenu de `docs/email-invitation.html`.
- Reset password : copier le contenu de `docs/email-recuperation.html`.

Ces modèles sont indispensables. Ils transmettent un hash à usage unique dans le fragment du lien, pas les jetons de session. La page efface le fragment de l’URL et demande un clic explicite avant confirmation. Ne pas conserver les modèles par défaut pour ce package.

## 5. Créer le premier administrateur

1. Dans Supabase Auth > Users, inviter votre propre adresse, après configuration des modèles.
2. Avant d’ouvrir le lien reçu, remplacer l’adresse dans `sql/02_premier_administrateur.sql`, puis exécuter ce script.
3. Vérifier qu’une seule ligne administrateur correspond à votre compte.
4. Ouvrir le lien, confirmer et choisir un mot de passe unique de 14 caractères minimum.
5. Configurer l’authentificateur TOTP avec la clé manuelle affichée, puis saisir le code.
6. Depuis l’accueil, ouvrir Administration et inviter un utilisateur de test.

Les invitations du panneau créent toujours des utilisateurs ordinaires. La promotion ou désactivation d’un administrateur se fait uniquement dans Supabase, pas dans le panneau. Cela empêche de désactiver le dernier administrateur depuis l’application. En cas de perte de l’authentificateur, le propriétaire du projet doit gérer le facteur depuis Supabase ; aucun contournement n’est intégré au site.

## 6. Recette avant mise en production

Suivre `docs/RAPPORT_CONTROLE.md`, notamment la liste des tests réels restant à réaliser. Tester d’abord avec des données non sensibles.

## Exploitation et limites

- Sessions conservées en mémoire du serveur : un redémarrage ou déploiement déconnecte les utilisateurs. Une seule instance est supportée. Pour plusieurs instances, il faut un stockage de sessions partagé sécurisé.
- Durée absolue 8 h, expiration après 30 min sans requête. Les outils ouverts effectuent une vérification chaque minute ; cette activité maintient la session jusqu’à la limite absolue.
- La désactivation bloque les nouvelles requêtes. Un outil déjà chargé est redirigé au contrôle suivant, normalement sous 60 s en ligne. Le navigateur peut retarder les contrôles en arrière-plan.
- Aucun serveur ne peut retirer une copie du code déjà téléchargée par un utilisateur autorisé. Ce package contrôle la distribution, pas la copie après autorisation.
- Les outils existants utilisent du stockage local pour certains réglages/sauvegardes. Celui-ci n’est pas cloisonné par compte. Utiliser un profil navigateur dédié par personne et ne pas partager une session de navigateur pour des données confidentielles. La déconnexion ne supprime pas les sauvegardes locales.
- Les outils métier historiques sont conservés, avec leurs scripts inline et dépendances. Leur audit XSS et leur recette fonctionnelle complète restent à faire avant un déploiement sensible. La CSP des outils est donc plus permissive que celle de l’administration. Ne pas importer de fichiers non fiables dans une session administrateur.
- Les bibliothèques et fonds de carte externes peuvent nécessiter Internet. Ce package n’est pas un dispositif hors ligne.
- Les journaux serveur contiennent des identifiants de comptes et d’événements, pas les mots de passe ni jetons. Prévoir une conservation et un accès adaptés.
- La limitation locale utilise l’adresse de la connexion réseau, pas un en-tête proxy non fiable. Derrière un proxy, plusieurs utilisateurs peuvent partager cette limite. Un filtrage/rate limiting en amont est recommandé pour une ouverture publique.

## Rejouer les tests

Sur une machine Node 24, dans le dossier du package : `npm test`.
Aucune dépendance npm n’est nécessaire au serveur ou aux tests HTTP.
Les tests utilisent exclusivement une simulation Supabase, jamais vos comptes réels.
`tests/local-preview.mjs` est un serveur de simulation limité à localhost : NE JAMAIS le déployer.

## Références techniques consultées

- [Supabase : clés API](https://supabase.com/docs/guides/api/api-keys)
- [Supabase : modèles e-mail](https://supabase.com/docs/guides/auth/auth-email-templates)
- [Supabase : sessions côté serveur](https://supabase.com/docs/guides/auth/server-side/advanced-guide)
- [Supabase Auth : contrat REST](https://github.com/supabase/auth/blob/master/openapi.yaml)
- [Render : service Node](https://render.com/docs/deploy-node-express-app)
