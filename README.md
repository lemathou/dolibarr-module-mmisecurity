# MMISecurity — Sécurité MMI : filtrage IP et durcissement de l'accès.

> Module Dolibarr **MMISecurity** (version 1.0), branche `20.0`.

## Fonctionnalités

### Fonctionnalités principales

- Filtrage des accès par IP (actions/hooks), configuration des plages autorisées.
- Page d'accueil et contrôles de sécurité.

### Écrans et menus

- **** — ``

### Pages

- `admin/about.php`
- `admin/setup.php`
- `mmisecurityindex.php`

### Configuration

| Constante | Type | Rôle |
|---|---|---|
| `MMISECURITY_IP_LIMITATION` | textarea | Adresses IP de connexion |

### Hooks

- Contextes : `main`, `login`
- Callbacks : `updateSession`, `afterLogin`, `login_check`

### Classes et composants

- `class/actions_mmisecurity.class.php`
- `lib/mmisecurity.lib.php`

## Prérequis

- Dolibarr >= 11.0 (branche `20.0` : Dolibarr 20.0).
- Modules MMI : `mmicommon`. **`mmicommon` doit être activé en premier.**

## Installation

1. Copier le module dans `htdocs/custom/mmisecurity` :

   ```sh
   cd htdocs/custom
   git clone <dépôt> mmisecurity
   ```

2. Dans Dolibarr : **Configuration → Modules**, activer d'abord `mmicommon`, puis ce module.
3. Vérifier les permissions dans la fiche des utilisateurs concernés.

## Licence

GPLv3 ou ultérieure — voir `COPYING`. Documentation sous GFDL.

## Changelog

Voir [CHANGELOG.md](CHANGELOG.md) (évolutions datées).
