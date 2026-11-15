# Rayman 2 — retour des API CD via un relais Wine filtré (15 novembre 2026)

## État de la référence

La capture utilisateur rayman2-cd-volume-raw.log ne compte que 34 lignes. Elle atteste GetDriveTypeW(F:) -> 5 puis un appel GetVolumeInformationByHandleW, **sans son résultat ni l'étiquette reçue par le jeu**. La commande indépendante wine cmd /c vol F: affiche RAYMAN2. La variante V4 avec chemins relatifs et scanner de CD original affiche malgré cela le dialogue initial Rayman 2 CD not found. Ce n'est pas la tête Robo-Pirate en jeu.

La routine originale vérifie le type DRIVE_CDROM (5) et les sept caractères de RAYMAN2, puis la longueur 7 (voir docs/rayman2-original-cd-volume-flow.md). Une trace d'entrée d'API ne prouve pas que la validation dans le jeu a réussi.

## Instrumentation contrôlée

Le script scripts/rayman2_cd_api_relay.py exige le binaire scan-only exact, SHA-256 14be1a73f6cb016d0ee3ba039b92bf7f339e078bab2980c3ea887968dfe2f133, vérifie que F: porte RAYMAN2, refuse d'écraser des rapports existants et refuse de modifier un réglage RelayInclude préexistant.

Il ajoute temporairement HKCU/Software/Wine/Debug/RelayInclude pour limiter les traces Wine +relay aux API GetLogicalDrives, GetDriveTypeA/W, GetVolumeInformationA/W/ByHandleW, GetLastError et MessageBoxA/W. Il retire cette **valeur temporaire** dans un finally. En cas d'arrêt brutal (SIGKILL ou panne), le nettoyage peut échouer : vérifier alors manuellement cette clé. Aucun EXE ni DAT du jeu n'est modifié.

Commande depuis le dossier du jeu, CD original toujours monté sur F: :

    curl -fL --retry 3 -o ./rayman2_cd_api_relay.py https://raw.githubusercontent.com/legluondunet/unsafedisk/feature/safedisc-135-rayman2-inspection/scripts/rayman2_cd_api_relay.py
    python3 ./rayman2_cd_api_relay.py --exe ./Rayman2-v4-cd-scan-only-test.exe --seconds 45

Cliquer **Annuler** au message CD not found. L'outil produit rayman2-cd-relay-diagnostic.txt (résumé) et rayman2-cd-relay-raw.log (trace limitée par la liste d'API). Si les noms existent déjà, choisir --out/--raw différents ; aucun fichier n'est écrasé.

## Interprétation

Un retour 0 d'un GetVolumeInformationA/W instrumenté indiquerait l'échec de cet appel. Un retour non nul ne prouverait pas à lui seul que le tampon de sortie contient RAYMAN2 ou que les comparaisons internes réussissent. L'absence de ligne +relay peut venir d'un chemin indirect non instrumenté : on ne conclura pas que l'API n'est pas appelée. Si ces traces sont insuffisantes, la meilleure étape sera un point d'arrêt lecture seule autour de 0x449158 et 0x449203, avant tout nouveau patch.

Les contrôles PE32 CD d'origine et V4-CD-routes (jouable avec CD) restent inchangés. Ce test n'est pas un décodage SafeDisc ou un correctif sans CD.

Validation : 12 tests unitaires/synthétiques exécutés localement, couvrant les SHA d'entrée, la protection contre l'écrasement, la sauvegarde/restauration de RelayInclude, les mauvaises étiquettes du volume et le filtrage du rapport. Aucun Wine réel n'a été lancé dans les tests.
