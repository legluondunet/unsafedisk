#!/usr/bin/env bash
# Rayman 2 / Wine: reversible A/B test for the lost ':' in the retail CD path.
# This is a diagnostic, not a no-CD patch. Run only from the installed game cwd.
set -Eeuo pipefail

CD_ROOT="${RAYMAN2_CD_ROOT:-/run/media/romain/RAYMAN2}"
EXE='./Rayman2-v4-cd-scan-only-test.exe'
EXPECTED_SHA='14be1a73f6cb016d0ee3ba039b92bf7f339e078bab2980c3ea887968dfe2f133'
ALIAS='./F'
LOG='./rayman2-v4-cd-relative-F-alias-test.log'

abort() { printf 'ERREUR : %s\n' "$*" >&2; exit 1; }
[[ -f "$EXE" && ! -L "$EXE" ]] || abort "exécutable CD-scan-only manquant ou lien symbolique : $EXE"
[[ "$(sha256sum -- "$EXE" | awk '{print $1}')" == "$EXPECTED_SHA" ]] || abort "empreinte de l'exécutable inattendue"
mountpoint -q -- "$CD_ROOT" || abort "CD non monté : $CD_ROOT"
[[ -d "$CD_ROOT/Data/World/Levels" ]] || abort "le répertoire Data/World/Levels est absent du CD"
[[ ! -e "$ALIAS" && ! -L "$ALIAS" ]] || abort "./F existe déjà : ne pas remplacer ni supprimer"
[[ ! -e "$LOG" && ! -L "$LOG" ]] || abort "journal déjà présent : $LOG"
if WINEDEBUG=-all wine reg query 'HKCU\Software\Wine\Debug' /v RelayInclude >/dev/null 2>&1; then
  abort "Wine RelayInclude est encore défini. Vérifier ce réglage avant le test."
fi
vol="$(WINEDEBUG=-all wine cmd /c 'vol F:' 2>&1)" || abort "Wine ne peut pas lire F: : $vol"
[[ "${vol^^}" == *RAYMAN2* ]] || abort "étiquette F: inattendue : $vol"

cleanup() {
  if [[ -L "$ALIAS" && "$(readlink -- "$ALIAS")" == "$CD_ROOT" ]]; then
    unlink -- "$ALIAS"
    printf 'Alias temporaire ./F supprimé.\n'
  elif [[ -e "$ALIAS" || -L "$ALIAS" ]]; then
    printf 'ATTENTION : ./F a changé, aucun retrait automatique. Vérifier manuellement.\n' >&2
  fi
}

ln -s -- "$CD_ROOT" "$ALIAS" || abort "création de l'alias temporaire impossible"
trap cleanup EXIT
printf 'Test : scanner CD original, chemins relatifs V1.\n'
printf 'Alias provisoire : %s → %s\n' "$ALIAS" "$CD_ROOT"
printf 'Le CD reste monté ; aucun DAT ni EXE n’est modifié.\n'
printf 'Dans le jeu, observer si la boîte CD introuvable réapparaît ; si non, démarrer une nouvelle partie.\n'
WINEDEBUG=-all wine "$EXE" 2>&1 | tee -- "$LOG"