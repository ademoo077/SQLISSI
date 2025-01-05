# SQLInjector - Advanced SQL Injection Scanner

SQLInjector est un outil avancé de détection et de test d'injection SQL. Inspiré de `sqlmap`, il permet de détecter des vulnérabilités potentielles dans des applications web en testant des paramètres spécifiques avec divers types de payloads d'injection SQL.

## Fonctionnalités

- **Tests d'injection SQL basiques :** Vérifie les vulnérabilités courantes.
- **Injection SQL aveugle :** Tests pour des cas où aucune réponse explicite n'est donnée.
- **Tests basés sur le temps :** Identifie les injections basées sur les délais de réponse.
- **Tests UNION :** Exploite la syntaxe `UNION SELECT` pour récupérer des données.
- **Récupération d'informations sur le DBMS :** Récupère la bannière, l'utilisateur actuel, et plus encore.
- **Crawling intégré :** Explore les URL liées à un domaine pour maximiser la couverture des tests.
- **Sauvegarde des résultats :** Génération de rapports en formats JSON et HTML.
- **Multithreading :** Améliore la vitesse grâce à des threads multiples.

## Installation

### Prérequis

- Python 3.7 ou plus récent
- pip (Gestionnaire de paquets Python)

### Étapes d'installation

1. Clonez ce dépôt ou téléchargez les fichiers.

   ```bash
   git clone https://github.com/ademoo077/SQLISSI.git
   cd SQLISSI
