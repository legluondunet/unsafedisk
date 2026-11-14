# Rayman 2 — Deux boucles d'initialisation d'API Win32 conservées dans le startup, supprimées dans GOG

**14 novembre 2026 — audit statique en lecture seule.** Ce document ne revendique ni décryptage SafeDisc, ni lancement réussi de l'exécutable original.

## Provenance des exécutables

| Entrée | Taille | SHA-256 |
| --- | ---: | --- |
| CD `Rayman2(3).exe` | 676 352 | `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3` |
| Référence GOG `rayman2(4).exe` | 1 468 928 | `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713` |

Les opcodes sont vérifiés dans la section `.text` réellement active de chaque PE32 et les descripteurs dans leur section `.data` : la section d'archive `.extra` de GOG n'est jamais comptée comme du code exécuté.

## Deux boucles non équivalentes

Le startup `0x449360..0x4494AA` (331 octets, identique dans CD/GOG) inscrit **7** à `[0x5113E8]` et **36** à `[0x5113F0]` sous l'argument `mode=1`. Le site `0x401EF8` transmet littéralement `1` à `0x449360`. Le choix de cette branche suppose cependant la garde globale `0x5113EC` initialisée à zéro et l'absence de modification externe avant le contrôle.

Les cinq `CALL rel32` à `0x44947C`, `0x449485`, `0x44948E`, `0x44949A`, `0x44949F` vers respectivement `0x4478A0`, `0x448DB0`, `0x448D80`, `0x447DE0`, `0x448E30` sont **strictement inchangés**. Les deux fonctions du milieu possèdent des boucles distinctes :

| Origine | Indices (avec compteur normal) | Sous-fonction | Effet démontré |
| --- | --- | --- | --- |
| `0x448DB0` | 0..6 (7 passages) | `0x447A90` | Lit la table de 7 DWORDs `[0x510BA4 + i*4]`, appelle un `GetModuleHandleA` obtenu via le descripteur masqué #0 (`CALL ECX` à `0x447ACE`) et écrit le résultat dans le même tableau ; avec `mode=1`, il saute la comparaison de validation supplémentaire |
| `0x448D80` | 1..35 (35 passages) | `0x447AF0` | Sélectionne un descripteur à **stride 76**, fait des tests sur le pointeur préexistant et peut écrire le nouveau pointeur API masqué à `[0x4A1400 + i*76]` |

Attention : les **42 passages** sont une conséquence du flot statique et des compteurs que le startup écrit normalement, **pas des appels réellement observés**. Le `CALL ECX` de `0x447A90` ne prouve pas à lui seul que tous les appels réussissent.

### Structure exacte du tableau

À `0x447B21`, `LEA ECX,[EAX+EAX*8]` donne `9*i`. À `0x447B24`, `LEA ESI,[EAX+ECX*2]` donne `19*i`. À `0x447B27`, `SHL ESI,2` donne **`76*i`**. Les instructions `0x447B2A` et `0x447B30` lisent respectivement les champs à **`0x4A1404 + 76*i`** et **`0x4A13D0 + 76*i`**, puis `0x447BC2` écrit dans le slot `0x4A1400 + 76*i` selon le résultat de la validation. Les 36 blocs `0x4A13D0 + 76*i` (i=0..35) sont identiques sur CD/GOG ; leurs 36 slots de pointeurs `+0x30` valent tous zéro sur disque.

Le descripteur #0 est celui du bootstrap `GetModuleHandleA`. Les indices 1 à 35 sont les 35 descripteurs Windows déjà identifiés par l'audit des 106 appels indirects modifiés.

### Mutation GOG

Dans l'exécutable GOG actif, les deux entrées de boucle à `0x448DB0` et `0x448D80` sont exactement `RET; INT3...` (les 16 premiers octets). Les CALL du startup restent intacts, mais n'effectuent plus les deux parcours. Les anciennes routines appelées à `0x447A90` et `0x447AF0` commencent désormais par des `INT3`. GOG remplace par ailleurs une partie des appels d'API dynamiques par des appels directs IAT, ce qui explique pourquoi les appels préservés vers des stubs `RET` ne constituent pas à eux seuls un dysfonctionnement.

Il est **faux** de conclure que toutes ces 42 opérations sont des vérifications de disque ou une routine de décryptage de `.ICD`. Leur rôle principal observé est le remplissage ou la vérification de pointeurs de modules/API nécessaires à plusieurs routines masquées. Ces fonctions sont aussi susceptibles d'être nécessaires à l'exécutable original si l'on conserve ses appels d'API indirects. **Ne pas les remplir d'`INT3` dans le CD.**

## Trois réactualisations ponctuelles dans une autre routine

L'inventaire de désassemblage complet montre trois autres appels directs **dans le corps original de `0x447DE0`** :

| Appel | Arguments `PUSH` avant l'appel | Destination |
| --- | --- | --- |
| `0x44818A` | flag=1, index=2 | `0x447A90` |
| `0x448196` | flag=1, index=24 (`0x18`) | `0x447AF0` |
| `0x4481A2` | flag=1, index=25 (`0x19`) | `0x447AF0` |

Les trois **instructions `CALL E8 rel32` et les six `PUSH`** sont vérifiés par octets et destinations sur le CD. Dans la `.text` GOG active, les trois plages `PUSH/PUSH/CALL` de 9 octets sont toutes `INT3`. C'est cohérent avec le remplacement antérieur du gestionnaire `0x447DE0`, mais ne prouve pas leur atteinte à l'exécution originale.

**Ces trois appels ne font pas partie des 42 itérations du démarrage** : ils relèvent d'un autre chemin, potentiellement parcouru si les conditions de la routine originale sont satisfaites. Le nombre total de résolutions effectivement réalisées à l'exécution reste inconnu.

## Reproduction

```sh
python scripts/rayman2_startup_resolver_loops_audit.py \
    --retail /prive/Rayman2_CD.exe \
    --gog /prive/Rayman2_GOG.exe

RAYMAN2_RETAIL_EXE=/prive/Rayman2_CD.exe \
RAYMAN2_GOG_EXE=/prive/Rayman2_GOG.exe \
  python -m unittest discover -s scripts \
  -p 'test_rayman2_startup_resolver_loops_audit.py'
```

Le programme refuse toute divergence de SHA-256, valide les opcodes des boucles complètes, toutes les destinations d'appels, les constantes de compteurs, les stubs GOG et les 36 descripteurs. Les tests locaux ont réussi : **10/10**, dont deux exercices contre les vrais exécutables et des mutations négatives de sept positions de code ou de données. La CI sans fichiers commerciaux exécute les huit tests synthétiques.

## Prochaine étape

L'expérience déterminante n'est plus de compter les appels statiques. Il faut observer un **démarrage original** et enregistrer le premier écrivain de `0x5113EC` ainsi que les pointeurs effectivement inscrits dans `0x4A1400 + 76*i`. Une éventuelle solution qui substitue les appels d'API masqués devra préserver les deux familles d'opérations tant qu'elles servent les fichiers DAT/GPT ou le lecteur de CD original.

Aucun code commercial, dump, ou patch exécutable n'est inclus dans les résultats.
