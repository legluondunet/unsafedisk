# Rayman 2 — 39 constructeurs de trampolines CD, trois vestiges dans GOG court-circuités par saut

**15 novembre 2026 — recherche statique en lecture seule, sans déchiffrement ni test du jeu.** Ce document complète les travaux existants sur le cache d'instructions (`rayman2-trampoline-iat-bridge-audit.md`, `rayman2-anti-tamper-evidence.md`) et les différences GOG (`rayman2-gog-retail-patch-dependency-preflight.md`). La propriété RW/non-exécutable de `.data` et la génération de stubs sont **déjà connues** ; la nouveauté est le **recensement croisé CD/GOG et la démonstration des trois chemins de saut qui laissent du vieux code machine non emprunté sur le chemin d'entrée normal**.

## Identité stricte des entrées privées

| Fichier | Octets | SHA-256 |
|---|---:|---|
| EXE provenant du CD `Rayman2(3).exe` | 676 352 | `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3` |
| Comparateur **GOG modifié**, `rayman2(4).exe` | 1 468 928 | `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713` |

L'analyseur vérifie la signature PE32, l'ImageBase et les sections, puis recherche les **séquences x86 exactes** ci-dessous uniquement dans la `.text` active : il ignore l'ancienne `.text` conservée en copie **non exécutable** dans `.extra` de GOG. Les 39 sites CD ont été recoupés avec les frontières d'instructions affichées par GNU `objdump` ; les occurrences positives sont protégées par des adresses attendues plutôt que par une simple somme.

## 1. Recensement des instructions qui commencent à fabriquer un trampoline

| Première écriture x86, après vérification de la frontière d'instruction | CD | GOG `.text` active |
|---|---:|---:|
| `MOV BYTE [ESI], 0xA1` (`MOV EAX,[imm32]` généré) | **19** | **3** |
| `MOV BYTE [ESI], 0x68` (`PUSH imm32` généré) | **2** | **0** |
| `MOV BYTE [EDX+0x510EA0], 0xA1` | **15** | **0** |
| `MOV BYTE [EDX+0x510EA0], 0xE9` (`JMP rel32` généré) | **2** | **0** |
| `MOV BYTE [EDX+0x510EA0], 0x68` | **1** | **0** |
| **Total de ces cinq motifs bornés** | **39** | **3** |

**Attention :** ce tableau inventorie **cinq formes d'instructions précisément définies** et leurs sites, **pas toutes les formes possibles de code généré**. Les 39 sites, le masque PE `.data = 0xC0000040` (RW sans bit EXECUTE) et `DllCharacteristics=0` sont confirmés. Le buffer `0x510EA0` se trouve dans la partie initialisée à zéro par le chargeur de `.data` (VirtualSize `0x776D0`, RawSize `0x7C00`), et la région de synchronisation du cache d'instructions couvre `0x464` octets. **Aucun état réel des protections de page ou incident DEP n'a été observé**, comme précisé dans les audits préexistants.

## 2. Les trois « survivants » GOG : présents sur disque mais évités à l'entrée

| Ancienne écriture conservée dans `.text` GOG | Saut GOG ajouté avant le générateur | Destination GOG | Suppression de l'effacement |
|---|---|---|---|
| `0x470061` | `0x470056 JMP rel8` | `0x4700B3`, puis `0x4700B7 JMP` | vers `0x47010E` |
| `0x47B1D3` | `0x47B1C8 JMP rel8` | `0x47B225`, puis `0x47B229 JMP` | vers `0x47B280` |
| `0x47B398` | `0x47B388 JMP rel32` | `0x47B441` | effacement entièrement contourné par le même saut |

Dans les **deux premiers** cas, GOG charge la valeur `0x517000` dans `EAX` (base de la section `.extra` qui archive l'ancienne `.text`) **avant** le saut. L'instruction de sauvegarde du retour dans le traitement est conservée après la destination. Cette observation recoupe les deux lecteurs du code d'origine déjà documentés, mais précise le rôle de la séquence de génération toujours présente sur le disque. Le **troisième** cas saute directement à une phase ultérieure de l'évaluateur et n'a pas de remplacement explicite `MOV EAX,0x517000` à cet endroit.

Pour les **trois** cas dans le CD, le code machine `LEA EDI,[ESI+0xF]`, les comparaisons de curseur, les appels à la PRNG et un saut conditionnel de retour établissent une boucle d'effacement portant sur **15 octets** après l'appel au stub, sur le chemin original où cette boucle est atteinte. Dans GOG, les sauts directs prouvent que ce nettoyage est **évité sur le chemin d'entrée normal de ces fonctions**. La PRNG initiale en tête de fonction demeure ; les 15 avances supplémentaires liées à l'effacement ne se produisent pas sur ces chemins GOG. Cela peut provoquer une différence d'état PRNG entre éditions, **mais on n'a pas mesuré les états en jeu** et les appels du stub et autres effets peuvent aussi influencer la séquence globale.

**Limite de portée décisive :** nous n'avons **pas** reconstruit un graphe de contrôle exhaustif avec toutes les branches indirectes, callbacks et entrées calculées. Le code résiduel n'est donc **pas prouvé inatteignable depuis absolument tous les chemins**. Nous avons démontré le contournement à partir du chemin normal d'entrée de chacune des trois fonctions.

## 3. Signification pour une future déprotection

Le fait que trois instructions de génération soient toujours **visibles** dans la `.text` GOG ne signifie pas que GOG utilise ces trampolines ni que ces mêmes octets peuvent être réutilisés comme une solution CD. Inversement, le total 39 du CD n'est **pas un décompte de 39 vérifications SafeDisc** : plusieurs de ces constructeurs sont de simples chemins de lecture et écriture de fichiers, et d'autres participent au moteur d'expressions. La comparaison avec GOG ne prouve pas l'origine du contrôle physique du CD ni le code de décryptage.

Pour distinguer un défaut de permission mémoire d'une vérification SafeDisc, une observation de l'exécution doit d'abord établir la protection réelle de la page du buffer lors de la première invocation d'un trampoline et identifier le résultat des callbacks `+0x2C` / `+0x30`. **Ne pas désactiver DEP globalement ni recopier en bloc les sauts GOG.** Les fragments d'objets des ressources `.GPT` et leurs paramètres restent indisponibles.

## 4. Reproduction

```bash
python scripts/rayman2_gog_dead_thunk_audit.py \
  --retail '/private/Rayman2(3).exe' --gog '/private/rayman2(4).exe'
python -m unittest discover -s scripts -p 'test_rayman2_gog_dead_thunk_audit.py'
```

L'audit est verrouillé aux SHA complets, vérifie les cinq ensembles de sites, les destinations de cinq sauts directs GOG, la copie non exécutable `.extra`, le buffer `.data` et les trois boucles d'effacement CD. **23/23 tests réussis localement** : 17 synthétiques + 6 validations sur les vrais fichiers privés ; les six tests propriétaires sont ignorés en CI sans les échantillons. Les mutations de test agissent uniquement sur des `bytearray` en mémoire. Aucun fichier du jeu, aucune nouvelle EXE, aucune capture de code original n'est incluse dans le dépôt ou l'archive de résultats.

**État : une différence de contrôle de flux GOG/CD désormais prouvée ; pas de déchiffrement SafeDisc, de correctif fonctionnel ni de validation en jeu.**
