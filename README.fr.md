<!-- SPDX-FileCopyrightText: 2026 Libre AI contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Vérifier un artefact avant de l'intégrer

Détecter un fichier modifié, absent ou ajouté et vérifier que les preuves fournies correspondent au contenu attendu.

- **Bibliothèque Rust `libre-ai-artifact`** : compare les fichiers au manifeste, aux tailles et aux empreintes annoncées ; refuse les preuves incohérentes ou manquantes pour une livraison.
- **Paquet TypeScript `@libre-ai/provenance`** : signe et vérifie un relevé de contributions avec une clé Ed25519 fournie par l'appelant.

## Essayer

Le code est en cours d'intégration locale. Placez `schemas-and-contracts` à côté de ce dépôt, puis lancez :

```sh
cargo test --locked
```

Les [exemples testés](tests/candidate_verification.rs) montrent les cas acceptés et refusés. Le paquet TypeScript se trouve dans [`packages/provenance`](packages/provenance).

Ces bibliothèques ne décident pas seules à qui faire confiance : l'application doit sélectionner les preuves et clés admises. Aucun paquet n'est publié sur un registre à ce stade.

[English](README.md)
