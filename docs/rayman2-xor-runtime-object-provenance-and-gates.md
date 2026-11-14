# Rayman 2 — provenance du déclenchement des deux plages XOR dans les objets du moteur

**14 novembre 2026 — analyse statique en lecture seule, limitée aux deux fichiers PE32 du propriétaire. Aucun `Rayman2.exe` déprotégé créé.**

## Échantillons et intégrité

- CD d'origine, `Rayman2(3).exe` : **676 352 octets**, SHA-256 `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`.
- Version GOG modifiée, `rayman2(4).exe` : **1 468 928 octets**, SHA-256 `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`.

GOG **n'est pas** un original commercial simplement décrypté, et son archive `.extra` de code original n'est pas du code actif. Ce document prolonge [l'analyse du décodeur XOR](rayman2-inplace-xor-executor-and-memory-scrub.md), sans attribuer arbitrairement le mécanisme à SafeDisc.

## Nouvelle chaîne d'appels, identique entre CD et GOG

Les huit `CALL E8 rel32` suivants ont été redécodés directement depuis les instructions des deux PE :

| Site | Cible | Rôle observé statiquement |
| --- | --- | --- |
| `0x4042A8` | `0x4045F0` | Appel lors d'une phase d'initialisation |
| `0x4045F4` | `0x404550` | Parcours des objets, avec l'argument littéral `0` |
| `0x404588` | `0x467210` | Prétraitement de l'objet, première liste |
| `0x404591` | `0x467350` | Décodage/exécution, première liste |
| `0x4045CC` | `0x467210` | Prétraitement, seconde liste |
| `0x4045D5` | `0x467350` | Décodage/exécution, seconde liste |
| `0x4673B7` | `0x481550` | Vérification/conversion de valeur typée |
| `0x4674C8` | `0x467130` | Construction des 16 callbacks d'accès au disque/fichier |

Quatre blocs complets sont **identiques octet par octet** dans le code actif des deux exécutables :

| VA de début | Longueur | SHA-256 des octets de la fonction |
| --- | ---: | --- |
| `0x404550` | 153 | `4cef57faf6969059bd1732ad13eee6aecee8e845cbd6ba08df47610a7c95692b` |
| `0x4045F0` | 204 | `821263233d13affb1d623465d08e7c244ec4e7a5cc35cfe68b5ac1a7cb2b6263` |
| `0x467210` | 308 | `b9721ba2595f392b1f306c0908bac5794f02e64a3f9003c64e45d3eddd280c7b` |
| `0x467350` | 590 | `b33fb63041764dfbd2a35ae1d591e7ad61b21484b4e6594053cf626d2ce37dc3` |

Ces quatre empreintes et les huit appels ont été vérifiés **une seconde fois par un script indépendant** sur les deux fichiers privés en local, en plus des validations CI de la branche.

## Deux listes et un drapeau d'objet, pas un appel direct à SafeDisc

Dans `0x404550` :

1. La première liste commence au pointeur global **`[0x4A6B1C]`**, parcourt les nœuds via `[EDI]`, et prend une structure d'objet via `[EDI+0x10]`.
2. La seconde part de **`[0x500FD0]`**, obtient un nœud initial par `[racine+8]`, puis suit `[EDI+0x14]`, avec la structure objet issue de `[EDI+4]`.
3. Sur les deux chemins, un pointeur d'objet non nul et le test **`[object_metadata+0x24] & 0x01000000`** constituent des conditions nécessaires à la suite, parmi d'autres contrôles de présence. Le caller `0x4045F0` transmet **`mode=0`** ; `TEST EBX,EBX / JNE` laisse alors ces appels s'exécuter.
4. Si l'objet passe ces contrôles, le programme transmet le même pointeur préparé successivement à `0x467210` et à `0x467350`.

**Le retour de `0x467210` n'est PAS testé entre ces deux appels.** Cette fonction dispose bien de ses propres validations et remplit des données typées liées à `[0x5117C4]`, mais cela ne la transforme pas automatiquement en autorisation d'exécuter le décodeur.

Le décodeur `0x467350` lui-même vérifie son argument `[EBP+8]` non nul, puis un pointeur calculé `[EBP-0x14]` non nul. Après appel à `0x481550`, il requiert un code de retour bas-octet **1** et une valeur résultante **2**. Ce sont des gardes **internes** supplémentaires : un objet portant le bon flag ne garantit pas que la routine XOR sera exécutée.

### Origine des données : les deux racines ne contiennent pas de payload dans le PE

La première racine `0x4A6B1C` est située dans `.data` file-backed et vaut **0x00000000** dans les deux PE. La seconde `0x500FD0` est au-delà du `SizeOfRawData` de `.data`, à l'intérieur de son `VirtualSize` : elle est donc **initialisée à zéro par le chargeur PE**. Les listes d'objets sont nécessairement peuplées plus tard, pendant la vie du processus.

**Nous ne connaissons pas le contenu chiffré des deux plages** au point d'appel indirect. Les fichiers originaux fournis pour cette comparaison n'incluent pas les données runtime de ces objets ni une capture mémoire du jeu. Une formule XOR correcte ne peut pas, à elle seule, fournir des octets absents des entrées.

## Géométrie : DWORDs à l'aller, octets à l'effacement

Le traitement `0x467350` :

- forme A et B à partir de valeurs d'objets, décode A puis B **par pas de 4 octets** ;
- transmet le **début de B** et l'adresse de la table de 16 callbacks à la fonction décodée au **début de A**, par `CALL [EBP-0x7C]` à `0x467535` ;
- peut modifier **le premier octet de B**, avec la lettre du lecteur stockée en `[0x4A6AD8]`, *après* son XOR mais *avant* l'appel indirect ;
- après retour, écrase successivement A et B **par pas de 1 octet**, à l'aide de la PRNG `0x448480`.

Un intervalle de longueur `n` parcourt **`ceil(n/4)` DWORDs** dans la boucle de décodage, mais exactement **`n` octets** dans la boucle d'effacement. Si `n` n'est pas divisible par 4, la lecture/écriture finale du décodage peut dépasser la borne logique. **Le programme a peut-être toujours des bornes alignées à l'exécution ; nous n'avons pas de capture permettant de le vérifier.** L'outil `--range-geometry` calcule uniquement ce risque géométrique pour quatre adresses de test ; il ne lit aucune mémoire commerciale.

## Expérience suivante, ciblée et réversible

Sur une copie de test autorisée, consigner uniquement les registres/pointeurs suivants sans modifier les instructions du jeu :

1. **`0x404583` / `0x4045C7`** : relever `EBX`, la liste parcourue, le pointeur d'objet et le drapeau lu à `+0x24`.
2. **`0x4673C4` et `0x4673D3`** : relever le résultat typé qui décide si l'exécution continue.
3. **`0x46750A`**, une fois les deux XOR terminés : relever les quatre DWORDs d'adresses **A=`[EBP-0x7C]`..`[EBP-0x28]` et B=`[EBP-0x78]`..`[EBP-0x24]`**. C'est *avant* le remplacement éventuel du premier octet de B.
4. **`0x467535`** : consigner les deux longueurs, le pointeur réellement appelé et une empreinte des plages décodées. Si une extraction des fragments est ensuite justifiée, conserver les octets uniquement dans l'espace de test personnel.
5. **`0x46753B`** : lire `EAX` comme valeur de retour **avant** les deux boucles d'effacement.

Une exécution peut ne jamais atteindre ce chemin : deux listes initialement vides, le flag d'objet, et le test typé conditionnent sa prise. **Ne pas forcer `0x5113EC` à 1, ne pas remplir les fonctions d'`INT3` ni copier aveuglément les modifications GOG**. Rien ne démontre encore que ce chemin constitue le chargeur SafeDisc, plutôt qu'une fonction du moteur conservée par les deux éditions.

## Reproduction

```bash
python scripts/rayman2_object_xor_gate_audit.py \
  --retail '/path/to/Rayman2(3).exe' \
  --gog '/path/to/rayman2(4).exe'

# Exemple purement synthétique : deux plages alignées de 8 et 12 octets
python scripts/rayman2_object_xor_gate_audit.py \
  --retail '/path/to/Rayman2(3).exe' \
  --gog '/path/to/rayman2(4).exe' \
  --range-geometry 0x400000 0x400008 0x401000 0x40100C

python -m unittest discover -s scripts -p 'test_rayman2_object_xor_gate_audit.py'
```

Le script est SHA-locked sur les deux binaires, interdit les entrées symboliques et de taille excessive, vérifie 4 SHA-256 de corps de fonction, 8 branches `CALL rel32`, et des ancres x86 individuelles, puis renvoie uniquement des métadonnées. Les tests synthétiques fonctionnent dans GitHub Actions ; leur test d'intégration commerciale reste optionnel et n'est pas distribué avec le dépôt.

**Statut : décodeur et provenance de déclenchement analysés ; aucun contenu réel déchiffré et aucune déprotection de l'EXE démontrée.**
