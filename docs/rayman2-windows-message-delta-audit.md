# Rayman 2 — audit des deux modifications du traitement des messages Windows

**14 novembre 2026 — comparaison statique en lecture seule.** Aucun exécutable commercial modifié, aucun déchiffrement complet revendiqué.

## Échantillons contrôlés

| Édition | Taille | SHA-256 |
|---|---:|---|
| CD original `Rayman2(3).exe` | 676352 octets | `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3` |
| GOG modifié `rayman2(4).exe` | 1468928 octets | `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713` |

La version GOG n'est **pas** un original CD simplement décrypté. L'analyse porte sur les VA des sections PE32 réellement chargées ; le contrôle de SHA-256 interdit de confondre les éditions.

## Chaîne et modifications vérifiées dans les octets x86

L'application configure un pointeur de procédure de fenêtre **`0x4022D0`** à `0x402039`. Cette procédure lit le second paramètre de la convention Win32 (`uMsg`) dans `EDI` à `0x4022DD`. Elle compare ce numéro à `0x218` (valeur Win32 de `WM_POWERBROADCAST`) puis à `0x400` (`WM_USER`), à `0x402520` et `0x402528`.

| VA | CD original | GOG actif | Effet statique |
|---|---|---|---|
| `0x402532` | `CALL 0x401B50` | cinq `NOP` | Supprime l'appel au répartiteur sur le chemin testé `EDI==0x400` |
| `0x402594` | `JNE 0x4025BE` | `JMP 0x4025BE` | Saute dans tous les cas la branche qui traitait notamment la valeur `0x400` dans un autre helper |

La seconde fonction commence à `0x402580`, lit un DWORD à `[ECX+4]` et le compare à `0x1C` (`WM_ACTIVATEAPP`) et `0x400` (`WM_USER`) aux VA `0x402589` et `0x40258E`. Son appel `CALL 0x401B50` à `0x40259E` est **encore présent et inchangé dans GOG**, mais le saut inconditionnel le contourne depuis ce chemin d'entrée. Attention : la provenance exacte du DWORD de ce second helper n'est pas démontrée par une trace runtime ; sa sémantique Win32 demeure une interprétation plausible au vu des constantes et du premier chemin WndProc.

La routine commune `0x401B50` retire `0x21` à un numéro de commande et effectue une sélection parmi cinq pointeurs de code à `0x401C30` (commandes `0x21..0x25`). La table est **identique** sur les deux éditions. Ce n'est pas un décodeur de données SafeDisc identifié.

## Interprétation et limite

Ces six octets modifiés appartiennent à la famille **traitement de messages/commandes**, pas à un point d'authentification de CD confirmé. On ne sait pas pourquoi GOG les désactive, ni si le programme original peut utiliser des messages applicatifs pour un contrôle indirect. **L'absence de preuve d'une vérification SafeDisc n'est pas une preuve que le contrôle n'existe pas.** Ne transplanter ni les cinq `NOP`, ni le `JMP` comme « crack » indépendant.

L'enquête de déprotection doit continuer sur les chemins de lecture physique du CD, la construction d'appels Win32 masqués et les valeurs runtime de `0x5113EC`, plutôt que sur ces différences d'interface.

## Reproduction

```
python scripts/rayman2_message_delta_audit.py --retail '/chemin/Rayman2(3).exe' --gog '/chemin/rayman2(4).exe'

RAYMAN2_RETAIL='/chemin/Rayman2(3).exe' RAYMAN2_GOG='/chemin/rayman2(4).exe' \
  python -m unittest discover -s scripts -p 'test_rayman2_message_delta_audit.py'
```

Validation locale : **12/12 tests**, y compris sur les deux vrais PE hash-verrouillés, ainsi que des copies synthétiques volontairement mutées. Le script publie seulement les métadonnées ; il ne crée pas d'exécutable.