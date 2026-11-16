# Rayman 2 — les deux racines du décodeur XOR proviennent du chargeur de niveaux \`.GPT\`

**14 novembre 2026. Investigation statique en lecture seule : aucune modification ni déprotection complète du programme original.**

## Portée et fichiers authentifiés

- Original CD fourni : \`Rayman2(3).exe\`, **676 352 octets**, SHA-256 \`7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3\`.
- Comparateur GOG modifié : \`rayman2(4).exe\`, **1 468 928 octets**, SHA-256 \`9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713\`.

GOG n'est pas un déchiffrement de référence garanti identique au programme CD. Le tableau de ses fichiers virtuels décrit des **noms et des longueurs déclarées**, jamais les véritables octets des fichiers du CD.

## Nouvelle chaîne de provenance (vérifiée sur les deux PE)

Les fonctions qui produisent les deux listes d'objets traversées par le décodeur XOR sont dans le *chargeur de ressources des niveaux* :

| Site | Opération vérifiée par octets |
| --- | --- |
| \`0x403A64\` | Récupère le chemin de base par \`0x492770\` |
| \`0x403A74\` | Formate le nom via \`0x45FE70\` et le littéral \`%s\\%s\\%s.gpt\` à \`0x49F334\` |
| \`0x403A81\` | Passe ce nom à \`0x44CD60\` pour ouverture |
| \`0x44CD8F\` | Appelle le pointeur Win32 \`CreateFileA\` (\`[0x49C058]\`), conserve le handle dans \`[0x5149BC]\` à \`0x44CD94\` |
| \`0x44CFA0\` | Lit depuis le **handle réel** \`[0x5149BC]\` par \`ReadFile\` importé à \`[0x49C04C]\` |
| \`0x44CFC0\` | Lit un DWORD et applique éventuellement une correction d'adresse |
| \`0x403B75\` | Affecte la deuxième racine de liste \`[0x500FD0]\` à partir de \`0x44CFC0\` |
| \`0x403BB1\` | Affecte la première racine de liste \`[0x4A6B1C]\` à partir de \`0x44CFC0\` |
| \`0x404550\` | Plus tard, parcourt les deux listes, filtre les objets par \`flag 0x01000000\` et appelle \`0x467210\` / \`0x467350\` |

Les **neuf CALL E8 rel32** déterminants, les **cinq régions de code complètes** et les ancres d'instructions sont **identiques entre les deux éditions**. C'est une vraie provenance de fichier, plus précise que le constat antérieur « racines en mémoire initialement nulles ».

**Important :** \`0x44CD60\` commence par tenter un vrai chemin de fichier local. Il peut composer un chemin CD avec \`%c:\\%s\` et proposer de réessayer en cas d'échec. Cette couche d'ouverture des ressources n'est pas équivalente à une authentification physique SafeDisc.

## Correction des DWORDs, distincte du décodeur XOR

Dans \`0x44CFC0\` :

1. \`0x44CFCC\` appelle \`0x44CFA0\` pour lire **4 octets** par \`ReadFile\`.
2. \`[0x5149C4]\` pointe vers un curseur de métadonnées, borné par \`[0x5149C0]\`.
3. Si le curseur est valide et si le DWORD brut correspond au DWORD \`[curseur]\`, le code lit les octets \`[curseur+4]\` et \`[curseur+5]\`, construit l'indice \`i = 10*octet4 + octet5\`.
4. Si le drapeau \`[0x5117E0+i]\` est non nul, \`0x44D01D\` ajoute au DWORD la base \`[0x5121E0+4*i]\` (arithmétique 32 bits).
5. Sur une entrée correspondante, \`0x44D024\` avance le curseur de **8 octets** ; en l'absence de correspondance, le curseur n'avance pas.

Cette mécanique ressemble à une **résolution conditionnelle d'adresses/pointeurs**, pas au chiffrement XOR des fragments exécutables de \`0x467350\`. Le lecteur \`0x44CFA0\` utilise directement \`ReadFile\`, pas l'un des lecteurs de ressources XOR à \`0x451090\`/\`0x451110\`.

Le nouveau \`resolve_word\` de l'outil simule cette résolution sur des DWORDs **synthétiques**, et rejette les indices qui dépasseraient le tableau de drapeaux de 2 560 octets observé entre \`0x5117E0\` et \`0x5121E0\`. **Le code machine original ne contient pas ce contrôle de borne**, donc ne pas le présenter comme une validation interne du jeu.

Les métadonnées de relocation réellement chargées, ainsi que les octets de la source \`.GPT\`, sont toujours inconnus dans les fichiers fournis.

## Catalogue de fichiers GOG — 3 716 noms, 71 niveaux GPT

Le parseur borné de la section non exécutable \`.extra2\` de GOG retrouve exactement **3 716 entrées**, avant le marqueur \`FFFFFFFF 00000000\`. Les noms/longueurs ne sont **pas le contenu des fichiers**.

| Extension | Nombre de références |
| --- | ---: |
| \`.GPT\` | **71** |
| \`.PTX\` | **71** |
| \`.SNA\` | **71** |
| \`.SND\` | **71** |
| \`.DSB\` | **71** |

Les 71 fichiers \`.GPT\` ont une taille déclarée **divisible par quatre**, et leur somme vaut **59 428 300 octets**. Leurs bases de noms correspondent exactement à celles des \`.PTX\`, \`.SNA\` et \`.SND\`. Une exception existe pour les \`.DSB\` : la série contient \`DATA\\GAME.DSB\`, mais pas de \`DATA\\WORLD\\LEVELS\\FIX.DSB\`.

Exemples de références déclarées :

| Index GOG | Chemin | Longueur déclarée |
| ---: | --- | ---: |
| 32 | \`DATA\\WORLD\\LEVELS\\FIX.GPT\` | 3 508 |
| 62 | \`DATA\\WORLD\\LEVELS\\ASTRO_00\\ASTRO_00.GPT\` | 656 660 |
| 67 | \`DATA\\WORLD\\LEVELS\\ASTRO_10\\ASTRO_10.GPT\` | 266 860 |
| 72 | \`DATA\\WORLD\\LEVELS\\BALL\\BALL.GPT\` | 12 760 |

L'alignement des *tailles déclarées* est compatible avec un format structuré en DWORDs, mais ne suffit pas à affirmer que tous les fichiers ou les plages de code ont des longueurs multiples de quatre.

## Conséquence pour le projet unSafeDisc

Le code de création des listes, l'appel au décodeur XOR, les accès GPT, les corrections des pointeurs et les quatre fonctions analysées précédemment restent **présents et identiques dans la version GOG**.

Cette chaîne documente donc un composant vraisemblablement essentiel du **moteur/chargeur de niveaux Rayman 2**, et ne saurait être supprimée au titre d'un hypothétique « chargement SafeDisc ». Une future déprotection de l'exécutable original doit la préserver.

**Pour analyser les véritables fragments XOR**, il faut soit un fichier \`.GPT\` original accompagné des tables/ressources permettant la reconstruction, soit une capture d'exécution en lecture seule des racines et des quatre bornes A/B avant l'appel \`0x467535\` et avant l'effacement. Aucun de ces éléments n'est fourni dans le PE original ou dans le catalogue virtuel GOG.

## Reproduction / tests

\`\`\`sh
python scripts/rayman2_gpt_root_loader_audit.py \
  --retail '/private/Rayman2(3).exe' \
  --gog '/private/rayman2(4).exe'
python -m unittest discover -s scripts -p 'test_rayman2_gpt_root_loader_audit.py'
\`\`\`

L'outil vérifie les SHA-256 complets, cinq empreintes de code identique, neuf appels, les ancres de lecture et de correction, les 3 716 enregistrements virtuels et les exceptions de catalogage. Il ne distribue aucun contenu de fichiers de jeu, n'écrit aucun exécutable et n'effectue aucun accès réseau.

**Validation locale : 13 tests réussis**, incluant l'intégration avec les deux véritables PE. En CI, les tests synthétiques restent exécutables sans distribuer les échantillons commerciaux.

**État final de cette étape :** provenance des pointeurs démontrée, formule de correction reproduite, aucun fragment réel extrait et aucun EXE original déprotégé.
