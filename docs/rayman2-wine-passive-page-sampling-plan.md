# Rayman 2 — surveillance passive des deux pages du tampon de trampolines

**15 novembre 2026 — méthode de validation runtime sous Wine, sans tracer ni modifier le jeu.** Étape complémentaire des analyses précédentes, notamment `rayman2-trampoline-iat-bridge-audit.md` et `rayman2-gog-dead-trampoline-paths.md`.

## Géométrie établie à partir du CD original

- Tampon de trampolines : **`[0x00510EA0,0x00511304)`**, soit `0x464=1124` octets, dans la partie zero-fill de `.data`.
- Sur un noyau Linux utilisant des pages de **4 Kio**, le tampon traverse **deux pages**, `0x00510000` et `0x00511000`. Un seul contrôle à `0x510EA0` peut donc manquer les permissions de la seconde.
- Garde du moteur à **`0x005113EC`**, sur la deuxième page, **`0xE8=232` octets après la fin du tampon**. Le flag de sélection de backend `0x00510BF4` est sur la première page.
- Indices de pointeurs Win32 masqués à `0x004A1400` (bootstrap), `0x004A1468` (FlushInstructionCache), `0x004A1498` (GetCurrentProcess). Leurs octets sur disque valent zéro et ne disent pas si le démarrage les remplit.
- L'en-tête PE exact annonce `.data = 0xC0000040` (RW, pas EXECUTE) et `DllCharacteristics=0` pour les deux éditions. **Il n'établit pas les permissions réellement attribuées par Wine ni un incident DEP**.

## Outil de diagnostic développé localement

Un script Python/Linux, `rayman2_wine_passive_pages.py`, a été préparé dans cette session et fourni avec son patch Git autonome en pièce jointe de la conversation. **Son intégration au dépôt n'est pas encore incluse dans ce commit documentaire.** Il se limite aux processus dont `/proc/PID/comm` correspond à `Rayman2.exe` ; il lit, sans breakpoint ni changement de page, les protections réelles `r/w/x` depuis `/proc/PID/maps`. Option `--sample-state` : lecture facultative de cinq DWORDs déterminés à l'avance via `process_vm_readv` ou `/proc/PID/mem` en lecture seule, sous réserve des permissions Linux. Les valeurs refusées sont marquées *inconnues*, jamais forcées à zéro.

Commande prévue depuis un terminal Linux lorsque l'utilisateur exécute lui-même son jeu original :

```sh
python3 scripts/rayman2_wine_passive_pages.py \
  --watch 60 --poll-ms 100 --sample-state --jsonl \
  > rayman2-pages-and-state.jsonl
```

Le processus de test ne doit pas être confondu avec un launcher Lutris ou Rayman2Fix. Ne pas désactiver DEP, détendre les permissions du noyau ou forcer `0x5113EC=1`.

## Validation réellement réalisée

- **26 tests Python réussis localement**, uniquement bibliothèque standard et tests synthétiques.
- Un programme C *de simulation non commerciale*, compilé en PIE, réserve **sans écraser d'autres mappings** (`MAP_FIXED_NOREPLACE`) les adresses ci-dessus ; il porte le nom de processus `Rayman2.exe` uniquement pour l'essai.
- L'observateur y a vu deux pages `rw-p` et lu le garde simulé `0x1234`, le flag `1` et les trois pointeurs factices. Une transition volontaire de la **seconde page seulement** par `mprotect` a ensuite été relevée comme `rw-p / r-xp`, le garde restant lisible. Aucun code injecté ou déchiffreur SafeDisc n'a été exécuté.
- Le patch Git local a été appliqué à un dépôt temporaire ; ses quatre fichiers ont été comparés octet pour octet avec les originaux.

**Ce qui n'a pas été observé :** un démarrage réel du jeu sous Wine/Windows, le premier écrivain de `0x5113EC`, un appel indirect au trampoline, une transaction avec le pilote SafeDisc ou une authentification échouée. L'observation passive périodique peut manquer des transitions courtes et ne révèle pas l'instruction qui écrit la garde.

L'objectif est d'obtenir un premier fait runtime discriminant, plutôt que de réutiliser comme correctif les `RET`, `INT3` et sauts spécifiques à GOG. Aucun exécutable CD déprotégé ou correctif jouable n'a été produit.
