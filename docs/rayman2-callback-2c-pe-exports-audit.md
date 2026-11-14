# Rayman 2 — le callback 0x2C scrute les exports PE des modules Windows

**14 novembre 2026. Audit statique en lecture seule, SHA-256 verrouillé sur deux fichiers du propriétaire. Pas de décryptage de l'ICD, de modification du jeu ni de preuve de contournement SafeDisc.**

| Rôle | Taille | SHA-256 |
| --- | ---: | --- |
| CD d'origine `Rayman2(3).exe` | 676 352 | `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3` |
| Édition GOG modifiée `rayman2(4).exe` | 1 468 928 | `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713` |

Le GOG n'est pas un simple décryptage fidèle du binaire CD. L'étude travaille sur les sections `.text` **actives**, alignées par RVA, et pas sur la copie inactive archivée dans `.extra`.

## Fait confirmé : l'index 11 de la table de callbacks reste identique, mais sa fonction change

La routine commune `0x467130` prépare une table de **16 pointeurs**. À `0x4671EB`, les deux programmes contiennent exactement `MOV DWORD PTR [EAX+0x2C],0x448DE0`. Cette routine de préparation est appelée aux sites `0x4674C8` et `0x47B01B`, qui sont des `CALL rel32` inchangés entre CD et GOG. Le `0x2C` correspond à l'index `11` (décimal) d'une table DWORD à base zéro ; il s'agit d'une entrée locale, **pas** d'un export Win32 direct.

- **CD :** la fonction `0x448DE0` lit `[0x5113EC]` dans son prologue ; quand cette valeur est nulle, elle lit `0x510BF4` à `0x448E04`. Selon le résultat, elle appelle `0x448610` (valeur zéro, chemin Toolhelp) ou `0x4481B0` (valeur non nulle, chemin d'énumération via PSAPI). Le retour provient du callee, **pas d'une constante fixée à l'avance**. Quand le guard n'est pas nul, la fonction enregistre une paire de bornes de code et renvoie zéro ; ce chemin de registration n'est pas identifié comme verdict SafeDisc.
- **GOG :** à **la même adresse `0x448DE0`**, les quatre premiers octets sont `33 C0 40 C3` (`XOR EAX,EAX; INC EAX; RET`) : **retour inconditionnel de `1`**. Le pointeur à l'index 11 reste intact. Cela modifie donc le **comportement d'un callback existant**, sans réécrire toute la table de consommateurs.

## Deux méthodes, même famille de contrôle

L'original vérifie cinq champs de pointeurs dynamiquement résolus aux VAs `0x447E04`, `0x447E11`, `0x447E1E`, `0x447E2B`, `0x447E38`. Chacun est suivi d'un `TEST EAX,EAX` et d'un saut conditionnel à la même destination `0x448075` si le pointeur manque. La table masquée d'API Win32 originale, **byte-identique** dans GOG et avec ses pointeurs nuls sur disque, associe ces cinq champs à :

1. index 19 : `CreateToolhelp32Snapshot` ;
2. index 20 : `Process32First` ;
3. index 21 : `Process32Next` ;
4. index 22 : `Module32First` ;
5. index 23 : `Module32Next`.

Les **trois écritures absolues** vérifiées de `0x510BF4` dans la routine CD `0x447DE0` sont : `0x447F4F` → 1, `0x448067` → 0, et `0x448077` → 1. Leur exécution dépend des conditions de contrôle, et **il ne s'agit pas de trois événements observés durant le jeu**. Le commentaire « 1 = chemin PSAPI, 0 = chemin Toolhelp » découle des branches de `0x448E04`, et pas d'une supposition sur la valeur qu'un système Windows donnera au démarrage.

### Ce que cherchent les deux méthodes : des noms d'exports PE

Le chemin **PSAPI** `0x4481B0` invoque `EnumProcessModules` (index 25). À `0x44834E..0x448378`, il suit l'en-tête PE (`e_lfanew` à `+0x3C`), le répertoire d'exports (`+0x78`) et les champs usuels de l'`IMAGE_EXPORT_DIRECTORY` : `AddressOfNames` (`+0x20`), `AddressOfFunctions` (`+0x1C`), `AddressOfNameOrdinals` (`+0x24`), `NumberOfNames` (`+0x18`). À `0x4483D7..0x448403`, il décode en continu un nom cible par soustraction puis XOR, et compare les octets au nom de l'export. Quand un module donne une correspondance, il incrémente son compteur à `0x448456`, retourné à `0x44846F`.

Le chemin **Toolhelp** `0x448610` utilise `CreateToolhelp32Snapshot`, `Module32First` et `Module32Next`. À `0x44880E`, il appelle l'auxiliaire `0x448970` qui parcourt également un répertoire d'exports PE et compare un nom cible encodé. La branche qui reconnaît une correspondance incrémente le compteur à `0x44881E`, retourné à `0x448964`.

Le retour réel du callback CD correspond donc à un **nombre de correspondances trouvées parmi les exports des modules inspectés**, avec de possibles différences selon le chemin. Le fait que GOG remplace ce résultat par `1` est plus significatif qu'une simple conversion de `CALL indirect` vers un import IAT. **Cela ne prouve toutefois ni le rôle du nom recherché (anti-débogage, intégrité, fonctionnalité normale), ni la valeur attendue par le programme appelant, ni la présence d'un pilote SafeDisc actif.** La provenance dynamique du paramètre contenant le nom cible reste à établir.

## Autre dépendance qui persiste dans GOG

Le nettoyage commun à `0x4494C7` lit le même indicateur `0x510BF4` et appelle conditionnellement l'import IAT `0x49C080`, résolu dans l'original en `FreeLibrary`. Cette portion est **byte-identique** dans GOG. Si l'on transpose arbitrairement les changements GOG vers le CD sans tenir compte de l'état des modules et de leur libération, on peut introduire une incohérence de ressources. L'absence de résolution runtime mesurée interdit de conclure que ce chemin de nettoyage est exécuté dans GOG.

## Reproduction et protection contre les faux positifs

```sh
python scripts/rayman2_callback2c_branch_audit.py \
  --retail '/private/Rayman2(3).exe' \
  --gog '/private/rayman2(4).exe'

RAYMAN2_RETAIL_EXE='/private/Rayman2(3).exe' \
RAYMAN2_GOG_EXE='/private/rayman2(4).exe' \
python -m unittest discover -s scripts \
  -p 'test_rayman2_callback2c_branch_audit.py'
```

L'analyseur est borné, vérifie le SHA-256 et la géométrie PE, refuse les divergences d'opcodes, décode les noms API sur des descripteurs de 76 octets, vérifie les deux `CALL` de construction de la table, les embranchements/compteurs des deux chemins, le retour constant GOG et la persistance du nettoyage. Il n'émet que du JSON de métadonnées. Les tests comprennent des mutations négatives et un contrôle qui modifie *uniquement* l'archive inactive `.extra` : le diagnostic actif ne doit pas changer, bien que le SHA de GOG change. Aucune donnée propriétaire n'est publiée sur GitHub.

**Limite majeure :** l'atteinte réelle du callback n'a pas été observée. Notre ancien blocage (`0x5113EC`, initialement nul en BSS mais avec écrivain runtime inconnu) demeure. La prochaine observation utile est un appel exécuté de `0x448DE0`, la valeur de `0x510BF4` à cet instant, l'argument cible encodé et le nombre effectivement retourné ; enregistrer uniquement les métadonnées nécessaires, sans dumper des ressources commerciales.
