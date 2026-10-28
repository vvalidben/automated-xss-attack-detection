# Modèle de rapport XSS — démonstration

> **Document illustratif à compléter. Aucun scan n'a été exécuté pour créer ce document.**
> Les champs entre crochets sont des espaces réservés, pas des résultats mesurés.

## 1. Périmètre et contexte
- Application : [laboratoire local autorisé, par exemple OWASP Juice Shop]
- Cible de démonstration : http://localhost:3000
- Autorisation et exclusions : [à renseigner]
- Date, version de l'application et commit du framework : [à renseigner]
- Niveau et scanners sélectionnés : [à renseigner]
- Statut : [terminé / partiel après pause / erreur]

## 2. Couverture observée
| Indicateur | Valeur issue du rapport réel |
|---|---|
| Pages découvertes | [à renseigner] |
| URLs et formulaires effectivement testés | [à renseigner] |
| Scanners exécutés et erreurs | [à renseigner par outil] |
| Candidats soumis à vérification navigateur | [à renseigner] |
| Candidats non vérifiés ou hors budget | [à renseigner] |

Ne pas confondre URLs découvertes et endpoints effectivement testés.
Un scan vide, interrompu ou limité ne démontre pas l'absence de XSS.

## 3. Fiche de constat à dupliquer
- Identifiant : [XSS-001]
- État de preuve : [observation de sink / candidat scanner / exécution confirmée]
- URL et paramètre anonymisés : [à renseigner]
- Source : [Playwright / XSStrike / DalFox]
- Preuve : [capture et extrait du rapport réel, sans jeton ni donnée personnelle]
- Résultat de la vérification navigateur : [confirmé / non confirmé / non vérifié]
- Sévérité et justification contextuelle : [à renseigner]
- Impact dans le périmètre autorisé : [à renseigner]
- Correction proposée : encodage adapté au contexte, API DOM sûres et
  assainissement du HTML lorsque nécessaire. La CSP constitue une défense
  supplémentaire ; elle ne remplace pas la correction de l'injection.
- Re-test après correction : [date, méthode et résultat à renseigner]

## 4. Limites
Documenter les erreurs Docker, timeouts, limites de crawl et de vérification,
zones authentifiées non couvertes et éventuelles pauses. Une alerte de scanner
requiert une analyse contextualisée ; un dialogue JavaScript n'est pas à lui
seul une évaluation complète de l'impact métier.

## 5. Avant un partage public
Utiliser uniquement un laboratoire autorisé. Retirer cookies, JWT, mots de
passe, identifiants de session, données personnelles et noms de systèmes tiers.
Vérifier aussi les captures et les fichiers HTML/PDF exportés. Conserver les
preuves détaillées dans un espace privé et ne publier qu'une synthèse autorisée.
