# Rayman 2 — sélecteur 5 : augmentation conditionnelle de 32 Mio avant GlobalAlloc

**14 novembre 2026 — audit binaire en lecture seule. Ce mécanisme n'est pas un décodeur d'EXE SafeDisc.**

## Sources

L'audit n'accepte que les deux fichiers exacts fournis par le propriétaire :

| Programme | Taille | SHA-256 |
| --- | ---: | --- |
| Original CD \`Rayman2(3).exe\` | 676 352 | \`7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3\` |
| Référence GOG modifiée \`rayman2(4).exe\` | 1 468 928 | \`9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713\` |

Une copie GOG n'est pas la sortie d'un décryptage original de référence. Tous les octets étudiés ci-dessous proviennent des **sections \`.text\` actives** correctement alignées par RVA, et non de l'archive \`.extra\`.

Ce rapport approfondit l'audit des [dépendances des modifications GOG](rayman2-gog-retail-patch-dependency-preflight.md). Parmi les 13 269 octets modifiés dans les \`.text\` correspondants, le groupe de **deux octets** à \`0x4500B0..0x4500B2\` modifie un déplacement de \`CALL\` et rien d'autre.

## Chaîne d'appels reconstituée

La table de 16 pointeurs à \`0x4501F0\` est identique CD/GOG. L'interpréteur à \`0x450000\` soustrait 1 au numéro de commande puis utilise cette table.

La **commande 5**, table index 4, atteint \`0x4500AF\`.

| Étape | Original CD | GOG modifié |
| --- | --- | --- |
| Sélecteur 5 \`0x4500AF\` | \`CALL 0x44F8D0\` | \`CALL 0x449080\` |
| Lecteur de DWORD \`0x44F8D0\` | 4 octets via \`0x450D90\` | **exactement la même fonction** |
| Fonction GOG \`0x449080\` | **pas de fonction valide à cette VA dans le CD original** | Appelle \`0x44F8D0\`, puis ajuste **une seule** valeur |
| Appel suivant \`0x4500B5\` | \`CALL 0x45DBE0\` | **inchangé** |
| Initialisation mode 0 \`0x45DBE0\` | \`CALL 0x442420\` | **inchangé** |
| Allocateur \`0x442420\` | \`CALL [0x49C07C]\` | **inchangé** |

**Indépendamment du sens supposé des fonctions**, l'import PE32 de l'exécutable CD étiquette précisément \`0x49C07C\` comme \`KERNEL32.dll!GlobalAlloc\` ; confirmé par \`objdump -p\`. La fonction \`0x442420\` utilise le retour de cet appel comme pointeur de bloc, qu'elle stocke dans un tableau de descripteurs (DWORD de début et de fin de zone).

À \`0x44F8D0\`, le programme :

1. conserve \`ECX\` sur la pile ;
2. passe le global de flux \`0x5116C0\`, \`count=1\`, \`size=4\`, et l'adresse du DWORD temporaire à \`0x450D90\` ;
3. renvoie le DWORD lu dans \`EAX\`.

L'édition GOG ajoute uniquement ce contrôle :

\`\`\`asm
0x449080: CALL 0x44F8D0
0x449085: CMP  EAX, 0x00632EA0
0x44908A: JNE  0x449091
0x44908C: ADD  EAX, 0x02000000
0x449091: RET
\`\`\`

\`0x00632EA0 = 6 500 000\` octets. \`0x02000000 = 33 554 432\` octets = **32 Mio**. Le résultat spécial devient **40 054 432 octets**. Toutes les autres valeurs de DWORD sont transmises sans changement.

L'original et le GOG appellent tous deux ensuite \`0x45DBE0\`, qui transmet le DWORD lu comme **quatrième argument** de \`0x442420\` et fixe le dernier argument à zéro. Cette branche choisit une allocation de taille en octets avec alignement sur quatre octets et \`GlobalAlloc(GMEM_FIXED=0, n)\`. Les tailles initiale et corrigée sont déjà multiples de quatre : le compte transmis pour ce cas est exactement **6 500 000** ou **40 054 432** octets, et non une taille supplémentaire créée par l'alignement.

L'appel à l'API est **à \`0x44248E\`**. Les instructions \`0x442504\` et \`0x442506\` inscrivent dans le tableau le pointeur de début retourné et une adresse de fin. Un autre chemin, commandé par la table index 14 (commande **15**, VA \`0x4500C2\`), utilise le même lecteur \`0x44F8D0\` mais une **autre initialisation à \`0x45DC20\`**, qui fixe la variable de mode \`0x516148\` à 1, au lieu de zéro ; ce chemin demeure inchangé.

## Ce que cette observation signifie — et ce qu'elle ne signifie PAS

**Établi par les octets :** GOG ajoute **32 Mio à une demande de mémoire précise, uniquement lorsque le DWORD du flux vaut 6 500 000**. Ce chemin fonctionne comme une augmentation conditionnelle de capacité pour une allocation du moteur.

**Non établi :** que la commande 5 et cette valeur sont effectivement rencontrées dans une partie, la raison pour laquelle GOG veut davantage de mémoire, que \`GlobalAlloc\` réussit, ou que cette différence change un contrôle d'authentification SafeDisc. Aucune donnée de niveau ni capture mémoire n'a été exécutée pendant cet audit. Le DWORD \`0x00632EA0\` n'apparaît **nulle part dans le binaire CD** sous forme de littéral direct, et une seule fois dans GOG, dans la comparaison décrite ci-dessus. Cela reste cohérent avec une valeur lue au runtime depuis un **fichier du jeu**.

Par conséquent, **il serait incorrect de présenter les deux octets modifiés de \`0x4500B0\` comme un « patch SafeDisc »**. Leur transplantation isolée vers le CD d'origine est de surcroît dangereuse : \`0x449080\` n'est pas dans l'exécutable original un nouveau helper GOG autonome. Une reproduction complète de cette amélioration mémoire demanderait un correctif distinct avec sa propre implantation, indépendant de l'étude de la protection.

## Reproductibilité et tests

\`\`\`sh
python scripts/rayman2_selector5_allocation_audit.py \
    --retail '/private/Rayman2(3).exe' \
    --gog '/private/rayman2(4).exe'

python -m unittest discover -s scripts \
    -p 'test_rayman2_selector5_allocation_audit.py'
\`\`\`

Le script vérifie **65 positions/instructions x86**, le tableau complet des **16 commandes**, les appels \`CALL E8 rel32\`, les paramètres du lecteur de 4 octets, la transmission de la taille, les deux modes d'allocation, ainsi que l'appel IAT de \`GlobalAlloc\`. Il impose les deux SHA-256 complets et ne renvoie que des métadonnées.

**Résultat local sur les vrais EXE : 11 tests réussis**, dont 100 000 valeurs synthétiques déterministes et cinq tests de mutations de code qui doivent échouer même quand l'empreinte test est temporairement adaptée. Les Git blobs des deux fichiers de code poussés dans la PR ont été comparés aux \`git hash-object\` de leurs originaux localement : **identité exacte**. En CI, les deux tests nécessitant les EXE privés sont ignorés sans altérer la couverture synthétique.

## Suite ciblée

- Si une exécution autorisée du jeu atteint la commande 5 : observer uniquement le DWORD lu dans \`0x44F8D0\`, puis la taille transmise à \`GlobalAlloc\`. Une simple trace d'adresses et de nombres suffit.
- Classer cette différence comme **correctif mémoire GOG**, non comme une déprotection confirmée.
- Continuer séparément la caractérisation des API masquées et du mécanisme d'authentification du CD. Le chargeur \`.GPT\`, les ressources \`.DAT\`, le décodeur XOR du moteur et les autolectures du code doivent être préservés tant que leur comportement réel n'est pas distingué de SafeDisc.

**Aucune exécution de jeu, aucun binaire commercial modifié, aucun EXE déchiffré ou publié.**
