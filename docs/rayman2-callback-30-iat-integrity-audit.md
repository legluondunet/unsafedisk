# Rayman 2 — callback `0x30` : contrôle conditionnel des pointeurs IAT, neutralisé dans GOG

**14 novembre 2026. Analyse statique reproductible en lecture seule, sans exécution d'un jeu et sans déprotection.**

## Échantillons strictement contrôlés

| Rôle | Fichier privé de l'utilisateur | Taille | SHA-256 |
| --- | --- | ---: | --- |
| CD original | `Rayman2(3).exe` | 676 352 | `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3` |
| Comparateur GOG modifié | `rayman2(4).exe` | 1 468 928 | `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713` |

La version GOG **n'est pas** un binaire original simplement déchiffré. L'archive `.extra` y contient du code ancien non exécutable et doit être exclue de l'analyse des instructions actives. Aucun fichier commercial, octet de code déchiffré ni correctif de l'EXE n'est publié.

## Nouveau résultat majeur : le callback `0x30` est différent du callback `0x2C`

La routine conservée `0x467130` construit un vecteur de **16 pointeurs de fonction** sur une pile temporaire. Dans les deux versions, l'instruction **`0x4671F4`** écrit **`0x448AB0`** à **`[EAX+0x30]`**. Les deux sites d'initialisation du vecteur (`0x4674C8` et `0x47B01B`) restent identiques. L'adresse 32 bits `0x448AB0` ne figure littéralement **qu'une fois** dans la `.text` active de chaque édition, dans l'opérande à `0x4671F7`; aucune instruction brute `E8 rel32` de la `.text` ne l'appelle directement. Les appels **indirects** à travers le vecteur restent possibles et ne sont pas observés dynamiquement.

La fonction CD **`0x448AB0..0x448D77`** fait exactement **712 octets**, SHA-256 `2709650e3632600e4c1e0ddfef3df51b304a060ecc8606c6dbd2bd59ef9c3fe3`. Elle présente un prologue gardé par `0x5113EC` (initialement nul en BSS). Dans la `.text` active GOG, les **trois premiers octets** de la même plage sont `33 C0 C3` (`XOR EAX,EAX; RET`), et **les 709 suivants** sont `INT3`. SHA-256 de cette région : `50ab7969a95ddfaa58fc08279448f6884f2bb10c0af68d8f55c2fe181aef6afc`.

**Ne pas confondre les deux callbacks :** l'offset `0x2C` compare des noms d'exports à travers les modules du processus et retourne un **nombre de modules correspondants** (GOG renvoie `1`) ; l'offset **`0x30`** parcourt la **table des imports de l'EXE lui-même** et teste un **écart de pointeurs** (GOG renvoie `0`). Le vecteur conserve les deux adresses d'origine dans GOG, même si les corps ont changé.

## Chaîne originale reconstruite par instructions

La reconstitution suivante porte sur des instructions vérifiées à leur **VA réelle** dans la `.text` du CD, et non sur un nom de fonction supposé :

| VA / sous-séquence | Provenance de la donnée et rôle |
| --- | --- |
| `0x448AE7..0x448AF3` | Récupère un argument `[EBP+8]` et conserve son premier DWORD à `[EBP-0x24]` ; il s'agit de la graine/du masque du descripteur transmis, pas d'une adresse Win32 connue sur disque. |
| `0x448B45..0x448B8E` | Construit un trampoline d'API masquée pour le descripteur #0 `GetModuleHandleA`, puis appelle avec l'argument `NULL` ; ce chemin est cohérent avec l'obtention de l'image principale du processus. |
| `0x448BF2..0x448BFC` | Lit `e_lfanew` puis le RVA **Import Directory** dans l'en-tête PE du module courant (offset NT `+0x80`). |
| `0x448C19..0x448C2C` | Lit les champs `OriginalFirstThunk` et `FirstThunk` des `IMAGE_IMPORT_DESCRIPTOR`, c'est-à-dire la source des noms importés et l'adresse des slots IAT. |
| `0x448C40..0x448C56` | Distingue les imports par ordinal, récupère le RVA `IMAGE_IMPORT_BY_NAME` et saute l'indice `Hint` de deux octets pour accéder au nom ASCII. |
| `0x448C6A..0x448C94` | Décode progressivement le **nom d'export chiffré transmis en argument** par `SUB` puis `XOR` et le compare aux octets du nom de l'import. |
| `0x448CC7..0x448CFE` | Si un nom correspond, sélectionne l'adresse du slot IAT, puis lit **l'adresse de fonction réellement contenue dans ce slot** via `MOV EAX,[EAX]`. |
| `0x448D08..0x448D52` | Recherche une entrée correspondante parmi les **36 descripteurs d'API** à partir de `0x4A13D0`, avec le stride exact **76 octets** (`0x4C`). |
| `0x448D5E..0x448D66` | Charge `[record+0x30]`, XOR avec le premier DWORD précédemment sauvegardé, puis calcule `SUB EAX,ECX`. |
| `0x448D6F` | Retourne zéro sur certains chemins où aucune comparaison complète n'a pu être réalisée. |

Lorsque **les deux recherches aboutissent** et qu'une fonction est présente dans la table IAT, la valeur de retour est, avec l'arithmétique x86 32 bits :

```text
actual = DWORD[live_IAT_slot]
expected = DWORD[matching_descriptor + 0x30] XOR DWORD[input_descriptor]
return (actual - expected) mod 2^32
```

Un retour nul peut donc signifier **adresse conforme** mais également **absence de correspondance** ou d'un prérequis. Il serait trompeur de présenter `0` comme une autorisation universelle observée. Nous n'avons pas la valeur réelle des pointeurs, leur masque au runtime ni la chaîne d'appel qui déciderait du traitement du retour.

## Le périmètre statique est réduit à 18 imports possibles

Un nouveau parseur PE32 indépendant de `objdump` a décodé la table d'importation sur **les deux vrais fichiers**. Ils ont **163 fonctions importées par nom** et un ensemble identique de noms, modules et adresses de slots IAT. Parmi les **36 exports masqués** déclarés dans les descripteurs du moteur, **18** figurent également parmi ces imports nommés ; **tous les 18 sont dans `KERNEL32.dll`**. Ils constituent le sous-ensemble que cette fonction pourrait confronter à une entrée IAT *dans l'image PE fournie*, si le code de niveaux lui transmet un descripteur approprié.

| Index de descripteur | API importée | Slot IAT VA |
| ---: | --- | --- |
| 0 | `GetModuleHandleA` | `0x49C064` |
| 3 | `QueryPerformanceFrequency` | `0x49C024` |
| 4 | `OpenEventA` | `0x49C0E4` |
| 5 | `CreateEventA` | `0x49C01C` |
| 6 | `ResetEvent` | `0x49C0E8` |
| 7 | `SetEvent` | `0x49C0F0` |
| 8 | `CreateFileA` | `0x49C058` |
| 9 | `WriteFile` | `0x49C034` |
| 10 | `ReadFile` | `0x49C04C` |
| 11 | `CloseHandle` | `0x49C0E0` |
| 12 | `SetFilePointer` | `0x49C048` |
| 14 | `QueryPerformanceCounter` | `0x49C060` |
| 18 | `GetFileSize` | `0x49C040` |
| 26 | `LoadLibraryA` | `0x49C084` |
| 27 | `FreeLibrary` | `0x49C080` |
| 29 | `SetFileAttributesA` | `0x49C054` |
| 30 | `GetFileAttributesA` | `0x49C050` |
| 32 | `SetErrorMode` | `0x49C0C8` |

Les **18 autres** noms masqués ne correspondent à **aucun import nommé** du binaire fourni, bien qu'ils soient accessibles par les mécanismes de résolution dynamique précédemment démontrés. Cela ne veut pas dire que leurs fonctions sont impossibles à utiliser, uniquement que le **test actuel de la table IAT statique** ne trouverait pas d'entrée ordinaire pour eux sans modification runtime.

**Limite importante :** nous ne savons **pas lequel** de ces 18 noms est effectivement demandé à `0x448AB0` par un objet de niveau. Les seules occurrences littérales de l'adresse du handler ne prouvent pas l'exécution du callback. Le code chargé depuis les `.GPT` peut transmettre l'argument via les **deux exécutants indirects** (`0x467535` et `0x47B072`), mais ses octets d'origine ne sont pas présents dans les deux exécutables PE fournis.

## Pourquoi ce résultat compte pour unSafeDisc

Le programme CD possède **au minimum un contrôle potentiel d'intégrité des fonctions importées**, indépendant de la recherche du volume logique `RAYMAN2`. GOG neutralise le même chemin avec `return 0` ; par ailleurs, GOG supprime les résolveurs Win32 originaux, mais **laisse les 163 imports nommés identiques**. Le changement GOG ne se réduit donc pas à l'absence d'import : il change le comportement du test de cohérence lui-même et sa dépendance à la résolution dynamique.

Il serait dangereux de copier ces octets GOG dans le CD : le résultat zéro peut avoir plusieurs significations, l'argument est inconnu et l'éventuel code consommateur n'est pas analysé. De plus, aucune comparaison au verdict d'authenticité physique du CD, aucun appel au pilote SafeDisc, aucun échec en jeu ni preuve de création d'un EXE autonome n'a été obtenue. Le décodeur XOR `0x467350` et les chargeurs `.GPT` sont des composants du moteur **conservés** dans les deux versions et doivent rester fonctionnels.

## Reproduction et contrôle négatif

```sh
python scripts/rayman2_callback30_iat_audit.py \
  --retail '/private/Rayman2(3).exe' \
  --gog '/private/rayman2(4).exe'

# CI : tests synthétiques uniquement ; fichiers propriétaires non distribués.
python -m unittest discover -s scripts \
  -p 'test_rayman2_callback30_iat_audit.py'

# Intégration locale si les deux originaux sont disponibles :
RAYMAN2_RETAIL_EXE='/private/Rayman2(3).exe' \
RAYMAN2_GOG_EXE='/private/rayman2(4).exe' \
python -m unittest discover -s scripts \
  -p 'test_rayman2_callback30_iat_audit.py'
```

L'analyseur vérifie les **SHA-256 complets**, la géométrie PE et les sections actives, **49 ancres x86** de la routine, les **deux SHA-256 des corps de 712 octets**, les **36 descripteurs identiques**, la table d'importation réelle, l'unique pointeur littéral du callback dans `.text`, et l'absence d'appel direct `E8 rel32` vers le handler. Il publie uniquement des noms d'API standard, adresses et métadonnées ; jamais des octets de jeu ou des pointeurs runtime non connus.

**Validation locale initiale : 22/22 tests réussis**, dont **15 purement synthétiques**, et **7 tests sur la paire exacte de fichiers privés**. En CI, les sept tests d'intégration se désactivent automatiquement en l'absence des deux entrées, et le jeu n'est jamais exécuté. Les mutations de copies en mémoire changent entre autres le chemin des imports, le décodeur des noms, le calcul d'écart, le pointeur de callback, les descripteurs ou le stub GOG : l'audit les refuse.

### Prochaine observation décisive

Identifier sur un lancement légal de Rayman 2 si le code indirect atteint réellement `0x448AB0`, quel descripteur il lui passe, la valeur IAT à cet instant et l'usage du retour. Une trace **passive** à cette adresse et à `0x448D66` distinguerait « mécanisme observé » de « mécanisme conservé mais dormant » sans patcher le jeu. Pour la branche `0x2C`, effectuer le même relevé à `0x448DE0` et récupérer le nom d'export transmis, sans confondre les deux retours.

**Pas de chargement de vrai CD SafeDisc observé, pas de reconstitution du binaire déprotégé, pas de publication ni de fusion de PR.**


## Précision — comparaison de préfixe et NUL

Une [contre-vérification dédiée](rayman2-iat-descriptor-nul-boundary.md) corrige un raccourci de l'exposé précédent : le nom décodé est comparé à un **préfixe** de l'import PE (mais, dans nos deux EXE, les 18 correspondances de préfixe sont toutes des correspondances de noms entiers). Surtout, les descripteurs encodés de 76 octets ne sont **pas** comparés octet par octet sur 76 octets : le chercheur d'enregistrement s'arrête au **premier octet nul égal**. Les enregistrements #3 et #26 contiennent un NUL dès les offsets 5 et 3, respectivement ; ils ne comparent donc que 6 et 4 octets (NUL compris) dans cette deuxième étape. Le modèle de différences de pointeurs reste valide **uniquement si la recherche de l'import et celle du record réussissent** ; il n'y a toujours aucune trace d'appel runtime ou de verdict SafeDisc.
