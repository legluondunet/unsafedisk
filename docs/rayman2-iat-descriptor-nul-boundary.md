# Rayman 2 — deux comparaisons différentes dans le callback +0x30 : préfixe et NUL

**14 novembre 2026 — recherche SHA-256-verrouillée, lecture seule.** Sur les deux exécutables privés d'origine : CD (676 352 octets, SHA-256 `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`) et GOG modifié (1 468 928 octets, SHA-256 `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`).

**Il faut corriger l'interprétation précédente :** l'algorithme ne compare *pas* systématiquement les 76 octets complets du descripteur à un enregistrement de sa table. Cette précision compte pour l'analyse de l'intégrité des imports et pour éviter toute fausse reconstruction SafeDisc.

## Les deux conditions, établies par les instructions originales x86

Le callback installé à l'offset `+0x30` du vecteur à 16 entrées, par l'instruction `0x4671F4`, pointe vers la fonction CD `0x448AB0`. GOG conserve l'adresse du callback mais remplace son corps par `XOR EAX,EAX; RET`, suivi de `INT3`.

**Première condition : recherche du nom d'import (`0x448C60..0x448CC7`).** Le nom encodé de l'argument du callback est décodé par soustraction puis XOR. Le code compare ses caractères au nom ASCII lu dans l'import PE et s'arrête dès que **la longueur déclarée du nom encodé** est atteinte (`0x448CA0` et `0x448CA5`), sans comparer le NUL qui devrait suivre dans l'import. C'est une égalité de **préfixe**, pas de chaîne complète. Contre-vérification : les deux PE fournis contiennent 163 imports nommés identiques. Parmi les 36 noms masqués, **18** sont des imports de KERNEL32 ; dans ces deux PE, les 18 correspondances de préfixe sont **également des égalités complètes**, donc la liste de candidats publiée précédemment reste correcte *pour ces fichiers*.

**Seconde condition : choix du descripteur (`0x448D12..0x448D5C`).** Le code compare par groupes de deux octets les données du descripteur transmis avec chacun des 36 enregistrements de 76 octets à partir de `0x4A13D0`. `0x448D22` / `0x448D24` et `0x448D36` / `0x448D38` arrêtent la comparaison dès qu'un **octet nul, égal de chaque côté, vient d'être comparé**. Ce n'est *pas* un `memcmp` sur 76 octets. En cas de différence, `0x448D47` / `0x448D4A` avancent au record suivant (`+0x4C`). L'étape suivante, si un record a été retenu, calcule `expected = [record+0x30] XOR DWORD[input]`, puis `actual_IAT - expected` à `0x448D5E..0x448D66`.

## Deux exceptions parmi 36 enregistrements

| Index | Nom décodé | Premier NUL dans le record | Fin du nom encodé | Octets comparés, NUL inclus |
|---:|---|---:|---:|---:|
| **3** | `QueryPerformanceFrequency` | offset **5**, au premier octet encodé | 30 | **6** |
| **26** | `LoadLibraryA` | offset **3**, dans la graine de quatre octets | 17 | **4** |

Pour les **34 autres**, le premier NUL se trouve immédiatement après le nom encodé, à l'offset `5+length`. Attention : même dans le cas #26, la **graine DWORD entière est comparée** puisque son quatrième octet nul est testé avant l'arrêt. C'est le reste du descripteur, éventuellement employé durant la première comparaison, qui n'est pas vérifié une deuxième fois.

**Démonstration sur des valeurs synthétiques (non issues du jeu) :** deux descripteurs utilisant une même graine dont le quatrième octet vaut zéro peuvent encoder deux noms différents (`LoadLibraryA` et `ReadFile`) tout en satisfaisant la *seconde* comparaison jusqu'au NUL de la graine. Si leur quatrième octet diffère, la comparaison échoue. Cette ambiguïté de sélection d'un record ne suffit ni à obtenir un résultat nul, ni à passer une vérification IAT, car **la première recherche d'import et la soustraction des pointeurs restent nécessaires**. Aucun argument réel de ces callbacks n'a été observé.

**Autre contrôle négatif :** les 36 signatures exactes composées de l'en-tête de cinq octets et du nom encodé complet apparaissent chacune **une fois et une seule** dans chacune des deux images PE, à l'emplacement attendu de `.data`. Aucune copie exacte n'est présente ailleurs dans les sections fichier, y compris dans l'archive GOG `.extra` non exécutable. Un nom remasqué différemment ou construit au runtime ne serait *pas* détecté par ce contrôle.

## Conséquence pour unSafeDisc

Cette analyse affine le contrat binaire du callback d'intégrité `+0x30`, mais ne démontre toujours **ni son exécution pendant le jeu**, ni l'export précisément transmis par les objets de ressources `.GPT`, ni un échec d'authentification du pilote/CD. Le callback précédent `+0x2C` recense certains modules exportant un nom. La provenance des fragments exécutés indirectement conduit vers le moteur de ressources, qui doit rester intact.

**Prochaine mesure déterminante :** sur un vrai démarrage CD, tracer **passivement** le premier appel à `0x448AB0` et l'argument à `[ESP+4]`. En déduire la longueur et le nom décodé en privé, relever l'adresse IAT correspondante, l'éventuel record sélectionné et le retour `EAX`. Observer ensuite quel code consomme ce retour. Ne pas greffer le stub GOG sur le CD, ne pas forcer la variable `0x5113EC` et ne pas supprimer le chargeur `.GPT`.

## Reproduction

```sh
python scripts/rayman2_descriptor_nul_audit.py --retail Rayman2-CD.exe --gog Rayman2-GOG.exe
python -m unittest discover -s scripts -p 'test_rayman2_descriptor_nul_audit.py'
```

Le script du dépôt valide les SHA-256 complets, les deux groupes de branches x86, les 36 descripteurs originaux/GOG et les imports. Les tests publics utilisent des données synthétiques ; les tests sur les deux PE privés restent optionnels via `RAYMAN2_RETAIL_EXE` et `RAYMAN2_GOG_EXE`. **Un audit local approfondi, disponible en archive utilisateur, a passé 20/20 tests** et les 22 tests du callback antérieur passent également (42/42 combinés). Aucune copie commerciale ou exécutable déprotégé n'est publiée.
