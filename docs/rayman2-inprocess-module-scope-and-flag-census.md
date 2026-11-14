# Rayman 2 — portée intra-processus du callback `0x2C` et disparition des écritures de `0x510BF4` dans GOG

**Recherche du 14 novembre 2026, lecture seule sur les deux EXE exacts fournis par le propriétaire.**

| Échantillon | Octets | SHA-256 |
|---|---:|---|
| CD `Rayman2(3).exe` | 676 352 | `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3` |
| Comparateur GOG `rayman2(4).exe` | 1 468 928 | `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713` |

La version GOG est fortement modifiée, **pas** une référence garantie « juste déchiffrée ». Seuls les octets de la `.text` **active** (et non l'archive `.extra`) permettent de tirer ces conclusions. Aucun jeu, pilote SafeDisc ou mémoire runtime n'a été exécuté ni modifié.

## 1. Le moteur cherche parmi les modules du *processus Rayman 2 lui-même*

Le précédent audit a prouvé que le callback d'offset `0x2C`, à l'adresse originale `0x448DE0`, cherche un export PE encodé via l'un des deux moteurs `0x4481B0` (PSAPI) et `0x448610` (Toolhelp). Le nouvel audit caractérise leur **portée précise** et leurs arguments réels.

**PSAPI.** L'original à `0x4481ED` appelle l'API masquée `GetCurrentProcess`, puis conserve son résultat dans EDI à `0x448202`. La séquence `0x4482A8..0x4482B1` empile ensuite, pour `EnumProcessModules` :

1. l'adresse du nombre d'octets effectivement renvoyés ;
2. la taille de tampon **`0x1000` octets** ;
3. le pointeur vers la liste de modules ;
4. **EDI, le pseudo-handle du processus courant**.

Le retour `lpcbNeeded` est divisé par **4** à `0x448321` pour obtenir un nombre de `HMODULE` sur x86. Si ce nombre vaut exactement **un**, le chemin `0x448329` retourne zéro sans scanner ce module ; dans le cas général (>1), il parcourt les adresses de base puis les structures `IMAGE_EXPORT_DIRECTORY`. Cela documente un comportement **statique conditionnel**, et ne prouve pas le nombre de modules réellement obtenus lors d'une session.

**Toolhelp.** À `0x4486BA` la routine originale pousse `0`, puis à `0x4486BC` pousse **`8`** avant d'appeler le pointeur masqué de `CreateToolhelp32Snapshot`. Dans l'API Windows, `dwFlags=0x8` est `TH32CS_SNAPMODULE` ; avec `th32ProcessID=0`, il s'agit de l'instantané des modules du processus courant. Elle lit ensuite la base du module depuis la structure de résultat à `0x4487F5`, pour parcourir ses exports. **Ce n'est pas une énumération de tous les programmes actifs.**

Ces deux chemins recherchent ainsi la **présence d'un export** parmi les modules chargés du jeu. Cette technique pourrait servir à trouver une fonction fournie par une DLL particulière (moteur, dépendance ou protection). **Le nom d'export passé par le code dynamique n'a pas été retrouvé dans les deux EXE seuls**, et les résultats ne prouvent ni `dplayerx.dll`, ni un verdict SafeDisc, ni le rôle exact du callback.

## 2. Six utilisations littérales du flag dans le CD, une seule dans la `.text` active GOG

La variable globale `0x510BF4` est située dans le segment `.data` virtuel **au-delà de ses octets présents sur disque** ; elle est donc **initialisée à zéro par le chargeur PE** dans les deux éditions.

Le programme original contient **exactement six occurrences** du DWORD little-endian `F4 0B 51 00` dans `.text`, chacune validée comme operand de l'instruction x86 indiquée (ce n'est pas seulement une recherche d'octets). Les VAs ci-dessous sont celles des **instructions**, et non des 4 octets d'opérande.

| Instruction du CD | Type | Chemin |
|---|---|---|
| `0x447B98` | Lecture | Résolution auxiliaire de modules |
| `0x447F4F` | Écriture **1** | Sélection conditionnelle PSAPI |
| `0x448067` | Écriture **0** | Sélection conditionnelle Toolhelp |
| `0x448077` | Écriture **1** | Sélection conditionnelle PSAPI, autre branche |
| `0x448E04` | Lecture | Choix de backend dans le callback `0x448DE0` |
| `0x4494C7` | Lecture | Chemin conservé de libération conditionnelle de module |

Dans `.text` GOG **active**, il ne subsiste que **la lecture `0x4494C7`**. Le callback est devenu `XOR EAX,EAX; INC EAX; RET` et l'initialiseur de backend a été neutralisé. L'archive **non exécutable** `.extra` de GOG contient bien une copie fidèle de l'ancienne `.text` CD et donc six anciennes références, mais **aucune de celles-ci n'est un nouveau consommateur exécuté**.

Ce recoupement explique une cohérence entre trois changements GOG : sélection de backend neutralisée, callback renvoyant toujours `1`, et nettoyage original conservé. **Il ne démontre pas que `0x510BF4` vaut zéro durant toute l'exécution GOG**, car des écritures par adresse calculée, une DLL extérieure ou du code généré restent théoriquement possibles.

## 3. La donnée manquante pour confirmer une vérification SafeDisc

L'appel au callback ne résulte pas d'un `CALL 0x448DE0` direct : sa **fonction est rangée dans la table de 16 callbacks** préparée à `0x467130` et fournie à des routines **exécutées indirectement** (`0x467535` et `0x47B072`). La provenance de ces objets dynamiques a été rattachée aux **fichiers de niveaux `.GPT`**, via la chaîne `0x403A74 → 0x44CD60 / 0x44CFC0 → 0x403B75 / 0x403BB1 → 0x404550 / 0x467350` documentée précédemment. **Les véritables octets de ces ressources et la valeur du nom d'export transmis ne sont pas présents dans les seules copies CD EXE/GOG EXE reçues.**

L'étude statique ne démontre donc **ni l'exécution réelle de ce callback, ni son utilisation comme authentification du disque**. Son retour constant `1` chez GOG ne suffit pas à justifier un patch du CD.

**Prochain discriminateur :** sur une installation CD d'origine autorisée, observer passivement l'entrée de `0x448DE0`, l'argument `[EBP+8]` (seulement longueur, structure et nom décodé si nécessaire), la valeur de `0x510BF4`, les modules parcourus et `EAX` au retour. Observer aussi le premier éventuel écrivain de `0x5113EC`. La capture de noms et d'adresses suffit : ne pas diffuser de code ni de ressources commerciales.

## 4. Validation reproductible

```bash
python scripts/rayman2_module_scope_flag_census.py \
  --retail '/private/Rayman2(3).exe' \
  --gog '/private/rayman2(4).exe'

RAYMAN2_RETAIL_EXE='/private/Rayman2(3).exe' \
RAYMAN2_GOG_EXE='/private/rayman2(4).exe' \
python -m unittest discover -s scripts \
  -p 'test_rayman2_module_scope_flag_census.py'
```

Le nouvel audit est SHA-256 verrouillé, réutilise les vérifications originales des callbacks, contrôle **8 signatures d'opcodes d'argumentation et de portée**, **6 instructions littérales du flag**, le recensement complet dans la `.text` active, le caractère BSS de l'adresse, et l'exclusion de l'archive `.extra`. Les **13 tests locaux** passent sur les vrais exécutables, ainsi que sur de multiples variantes volontairement modifiées en mémoire. Les tests d'intégration du dépôt sautent automatiquement si les binaires privés ne sont pas fournis. Aucun code commercial n'est commité.

**Résultat : portée d'inspection et dépendance de nettoyage mieux établies ; aucun nouvel exécutable déprotégé, aucune authentification SafeDisc réelle observée.**
