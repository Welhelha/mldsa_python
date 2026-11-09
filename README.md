# Tests ML-DSA pour Aries Askar Python

Ce dépôt fournit une suite de tests d’intégration pour l’implémentation ML-DSA du wrapper Python d’[Aries Askar](https://github.com/Welhelha/askar). Il vérifie les variantes ML-DSA-44, ML-DSA-65 et ML-DSA-87 ainsi que la non-régression des signatures Ed25519 et P-256.

> Ce dépôt est un banc de tests, pas une bibliothèque Python ML-DSA autonome. Le code Aries Askar testé est récupéré et compilé par la configuration pytest.

## Prérequis

- Python 3.10 ou ultérieur
- Git
- Rust et Cargo
- Une chaîne de compilation compatible avec les dépendances Rust

Au premier lancement des tests, `tests/conftest.py` récupère une révision épinglée d’Aries Askar dans `tests/.cache/askar`, puis compile la bibliothèque avec la fonctionnalité `mldsa`. Git et Cargo doivent donc être accessibles; un accès réseau est requis pour récupérer le dépôt et les dépendances si ceux-ci ne sont pas déjà présents dans le cache.

## Installation et lancement

Depuis la racine du dépôt, créez un environnement virtuel et installez pytest :

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pytest
```

Lancez ensuite la suite complète :

```bash
python -m pytest -q
```

Pour voir les cas de test détaillés :

```bash
python -m pytest -v tests/test_mldsa.py
```

La configuration de test compile le wrapper Rust au lancement. La première exécution peut donc prendre davantage de temps que les suivantes.

## Couverture

Les tests vérifient notamment :

- les tailles et identifiants de clés et signatures des trois variantes ML-DSA;
- la génération à partir d’une seed et la génération aléatoire;
- la signature et la vérification de messages de différentes tailles;
- le rejet des entrées invalides et des signatures altérées;
- les imports/exports de clés brutes et JWK AKP;
- les opérations concurrentes et la persistance SQLite;
- la non-régression Ed25519/P-256.