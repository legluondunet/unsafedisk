# Rayman 2 — Audit des dépendances avant reconstruction de l'EXE CD

**14 novembre 2026. Analyse en lecture seule sur les deux PE32 exacts fournis par le propriétaire.** Aucun jeu, fichier commercial, CD, pilote SafeDisc ou environnement Windows/Wine n'a été exécuté.

## Entrées et limites

| Source | Taille | SHA-256 |
| --- | ---: | --- |
| EXE original issu du CD, \`Rayman2(3).exe\` | 676 352 | \`7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3\` |
| GOG modifié, \`rayman2(4).exe\` | 1 468 928 | \`9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713\` |

Le GOG n'est **pas** le binaire CD simplement décrypté : ses sections supplémentaires, son catalogue virtuel, ses modifications de chemins et ses interceptions d'API constituent des changements distincts. Le but de cet audit n'est **pas** de transplanter les octets modifiés ; il est d'identifier les dépendances sans lesquelles une tentative de reconstruction serait erronée.

## Les 307 octets non couverts par les trois grandes régions

Comparaison des sections \`.text\` actives par RVA \`0x401000..0x49B200\`, longueur **631 296 octets**, et non par position de fichier : les empreintes CD et GOG donnent exactement **13 269 octets différents**, répartis en **102 séquences contiguës**. En regroupant les changements séparés d'au plus 512 octets inchangés, on obtient dix zones : trois grandes (7 704 + 3 646 + 1 612 = **12 962** octets modifiés) et **sept petites zones totalisant 307 octets**.

| Petit groupe d'adresses VA, fin exclue | Octets différents | Classification par octets vérifiés |
| --- | ---: | --- |
| \`0x401D8E..0x401DEE\` | **94** | Chemin de répertoire Windows remplacé par \`.\` ; sa construction de sous-dossier est court-circuitée |
| \`0x402532..0x402595\` | **6** | Un \`CALL 0x401B50\` devient 5 NOP, un saut \`JNE\` devient \`JMP\` inconditionnel |
| \`0x40593D..0x405A4C\` | **33** | Trois appels au répertoire Windows sont remplacés par le texte \`.\` |
| \`0x4500B0..0x4500B2\` | **2** | Déplacement relatif d'un \`CALL\` vers un auxiliaire **nouveau dans GOG** |
| \`0x46713B..0x4671F4\` | **135** | 16-entry callback vector: 12 Windows API masquées dans CD ; 11 émulations de fichiers GOG et un import direct dans GOG (déjà analysé) |
| \`0x470051..0x470267\` | **25** | Lecture de code redirigée vers l'archive GOG ; \`ShellExecuteA\` désactivé dans une autre routine |
| \`0x47B1C3..0x47B38C\` | **12** | Second lecteur de code redirigé vers l'archive GOG et court-circuit de construction d'appel masqué |
| **Total** | **307** | Ne pas déduire la raison d'une modification de son seul emplacement |

### Dépendance A : quatre appels \`GetWindowsDirectoryA\`

L'original appelle l'import Win32 **\`KERNEL32!GetWindowsDirectoryA\`** via le pointeur IAT \`0x49C0B4\` après deux paramètres de pile (\`0x104\`, pointeur de tampon), à \`0x401D94\`, \`0x405943\`, \`0x4059C3\`, \`0x405A46\`. GOG remplace ces appels par l'initialisation d'un tampon contenant \`.\`. À \`0x401D8E\` l'ancienne construction de sous-dossier et ses vérifications sont ignorées par un saut jusqu'à \`0x401DEE\`.

Des chaînes proches dans le code d'origine incluent \`/UbiSoft\`, \`/ubi.ini\` et \`/UbiSoft/Ubi.ini\`. Ces substitutions sont cohérentes avec une **portabilisation du chemin de configuration** ; elles ne constituent *pas* la preuve d'une authentification SafeDisc.

### Dépendance B : la modification de **deux octets** n'est pas autonome

Dans la table de branchement \`0x4501F0\`, **16 entrées** sont inchangées. Le sélecteur de valeur **5** renvoie à \`0x4500AF\`.

- CD : \`0x4500AF CALL 0x44F8D0\`
- GOG : \`0x4500AF CALL 0x449080\`

Le GOG insère à **\`0x449080\`** un nouveau sous-programme qui appelle à son tour \`0x44F8D0\`. Il compare \`EAX\` à la **valeur** \`0x00632EA0\` ; en cas d'égalité, il ajoute \`0x02000000\` à \`EAX\` avant le retour.

**Observation décisive :** dans le PE CD, \`0x449080\` est *au milieu des octets d'une instruction de la recherche du CD*, et n'est **pas** le point d'entrée d'une fonction. Reporter seulement les deux octets du déplacement de l'appel GOG dans l'original ferait exécuter des octets inadaptés. La constante \`0x00632EA0\` est comparée comme **valeur de retour**, pas déréférencée ici : ne pas la confondre avec un pointeur valide.

La nature du cas 5 et de son encodage d'une valeur de retour reste à confirmer par observation. Cet exemple suffit à interdire une greffe de correctif local sans analyse de ses dépendances.

### Dépendance C : les adresses d'archive GOG n'existent pas dans le PE CD

| En-tête / structure | CD | GOG |
| --- | ---: | ---: |
| \`ImageBase\` | \`0x400000\` | \`0x400000\` |
| \`SizeOfImage\` (RVA) | **\`0x117000\`** | **\`0x1D7000\`** |
| \`.extra\` code original archivé, non exécutable | **absente** | **VA \`0x517000\`** |
| \`.extra2\` catalogue fichiers virtuels | **absente** | **VA \`0x5B3000\`** |

La section \`.extra\` de GOG contient à **VA \`0x518000\`**, c'est-à-dire \`.extra+0x1000\`, une copie *bit pour bit* des **631 296 octets** de la section \`.text\` CD originale. Ce décalage \`0x1000\` reproduit le RVA de la section d'origine.

Deux fonctions d'expressions, \`0x470000\` (type \`0x170\`) et \`0x47B170\` (type \`0x11B\`), changent dans GOG pour utiliser \`0x517000\` comme **base de module de remplacement**, au lieu du module actif. C'est une preuve de préservation des **lectures du code original malgré les modifications GOG**, mais pas à elle seule d'un verdict de protection.

**Les VA \`0x517000\`, \`0x518000\` et \`0x5B3000\` ne sont mappées dans aucune section de l'EXE CD**. Les recopier aveuglément dans le CD créerait des lectures non valides selon son image PE déclarée. Un éventuel binaire original autonome devrait soit conserver ses propres lectures de code, soit recréer explicitement une architecture et des données appropriées, en fonction de la finalité prouvée des routines.

### Dépendance D : autre modification à ne pas assimiler au DRM

À \`0x470256\`, GOG remplace les 17 octets de préparation et d'appel Win32 **\`SHELL32!ShellExecuteA\`** par des NOP. Il s'agit de l'action d'une routine voisine d'expression du moteur (type \`0x171\`), et non d'une preuve de décodage SafeDisc. De même, les deux changements autour de \`0x402532\` et \`0x402594\` neutralisent un traitement de message ; le rapport ne prétend pas avoir identifié une authentification DRM à cet endroit.

## Point de méthode et véritable état du projet

Le programme CD possédé est déjà un **PE32 avec une très grande section de code x86 lisible** et le point d'entrée normal \`0x45FCC0\`. Le fait qu'il possède une protection CD SafeDisc ne prouve pas qu'il reste une section entière à décrypter. Les autres pièces critiques peuvent être **le chargement**, **la sélection d'API**, **les données CD**, **les autolectures de code** ou des contrôles en jeu.

Ce constat n'établit pas qu'il fonctionne sans le disque, que tous les contrôles sont désactivés ou que l'ICD fourni soit authentique. L'exécutable original ne possède pas de chaîne littérale \`SECDRV.SYS\`, \`RAYMAN2.ICD\` ou \`DeviceIoControl\` ; la présence de ces noms dans le catalogue GOG ne constitue pas la preuve de leur invocation. Des chargements indirects ou externes restent possibles.

**Conclusion opérationnelle :** ne pas reprendre les modifications GOG comme patch indépendant. D'abord déterminer quels chemins sont nécessaires au runtime CD et quelles substitutions ont des dépendances sur de nouvelles sections ou fonctions. Conserver les chargeurs de données DAT/GPT, le décodeur XOR du moteur et les autres routines communes.

## Vérification et reproduction

\`\`\`sh
python scripts/rayman2_patch_dependency_audit.py \
  --retail '/private/Rayman2(3).exe' \
  --gog '/private/rayman2(4).exe'
python -m unittest discover -s scripts \
  -p 'test_rayman2_patch_dependency_audit.py'
\`\`\`

L'outil vérifie les **deux SHA-256 complets**, l'alignement PE32, les **dix zones de différences**, la table d'aiguillage des 16 sélecteurs, la présence du nouvel auxiliaire, les quatre substitutions de répertoire, deux branches de message, les deux changements de lecture de code et les bornes des sections ajoutées. Il n'écrit aucun EXE et retourne uniquement des métadonnées. **11 tests privés locaux réussis**, incluant deux fichiers réels et des modifications négatives temporaires dans la mémoire du test ; GitHub Actions exécute les tests synthétiques sans échantillons commerciaux.

**Étape suivante réellement discriminante :** capturer la valeur renvoyée par \`0x44F8D0\` dans le cas **sélecteur 5** de \`0x4500AF\`, et enregistrer les objets de type \`0x170\` / \`0x11B\` effectivement interprétés. En parallèle, déterminer les exigences de chargement SafeDisc distinctes du disque logiquement présent. Une reconstruction ne pourra être considérée fonctionnelle qu'après exécution et validation en jeu sur la version CD d'origine.

**Aucun binaire du jeu décrypté, compilé ou diffusé ; aucune release ; aucune fusion dans \`main\`.**

## Complément — messages Windows

Les six octets modifiés autour de 0x402532 et 0x402594 ont désormais leur propre [audit des branches Windows et des messages `WM_USER`](rayman2-windows-message-delta-audit.md). Il confirme les sites d'appel et les sauts sur les deux PE d'origine sans les attribuer à une authentification SafeDisc. La provenance runtime du champ utilisé par le second helper demeure inconnue.
