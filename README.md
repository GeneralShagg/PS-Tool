# Windows Repair and Maintenance Tool

This PowerShell script provides a set of tools for repairing and maintaining a Windows system. It offers a menu-driven interface to access various functionalities aimed at improving system stability and performance.

## Prerequisites

- **PowerShell 7:** The script is designed to run with PowerShell 7. It includes a check and will attempt to relaunch with PowerShell 7 if started with an older version.
- **Administrator Privileges:** The script requires administrator privileges to perform many of its functions. It includes a check and will attempt to restart itself with administrator rights if necessary.

## How to Run the Script

1.  **Download the Script:** Save the `repair-tool.ps1` file to your local machine.
2.  **Open PowerShell 7:** Ensure you are running PowerShell 7. You can start it directly, or the script will attempt to relaunch in PowerShell 7 if run with an older version.
3.  **Navigate to the Script Directory:** Use the `cd` command to navigate to the directory where you saved the script.
    ```powershell
    cd Path\To\Script
    ```
4.  **Execution Policy:** If you haven't run PowerShell scripts before, you might need to adjust your execution policy. The script attempts to set the execution policy to `RemoteSigned` for the current user if it's not already set. If you encounter issues, you can set it manually in an administrator PowerShell window:
    ```powershell
    Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
    ```
5.  **Run the Script:** Execute the script using the following command:
    ```powershell
    .\repair-tool.ps1
    ```
    The script will check for administrator privileges and attempt to restart as administrator if needed.

## Features

The script presents a menu with the following options:

1.  **Scan and Réparation de Windows:**
    *   **Scan et réparation des fichiers Windows (sfc /scannow):** Runs the System File Checker to scan and repair corrupted or missing system files.
    *   **Scan du magasin Windows (DISM /Online /Cleanup-Image /ScanHealth et /CheckHealth):** Checks the health of the Windows Component Store.
    *   **Réparation du magasin Windows (DISM /Online /Cleanup-Image /RestoreHealth):** Repairs any corruption found in the Windows Component Store.

2.  **Effectuer la mise à jour des applications avec winget:**
    *   **Afficher la liste des mises à jour disponibles:** Shows all packages that have available updates via winget.
    *   **Mettre une application à jour:** Allows you to specify a single application to update.
    *   **Mettre toutes les applications à jour:** Attempts to update all installed applications using `winget upgrade --all --include-unknown`.

3.  **Effectuer les mises à jour Windows Update:**
    *   **Afficher les mises à jour de sécurité disponibles:** Lists available security updates.
    *   **Afficher les mises à jour optionnelles disponibles:** Lists available optional updates.
    *   **Effectuer toutes les mises à jour de sécurité:** Installs all pending security updates and may trigger an automatic reboot.
    *   **Effectuer toutes les mises à jour optionnelles:** Installs all pending optional updates and may trigger an automatic reboot.
    *(This functionality relies on the `PSWindowsUpdate` module, which the script will install if not present.)*

4.  **Défragmentation et optimisation du disque dur principal:**
    *   **Vérifications des erreurs du disque dur Principal (chkdsk C: /scan):** Scans the main drive for errors.
    *   **Vérifie le système de fichiers et les métadonnées (chkdsk /scan):** Performs a non-intrusive scan of the file system.
    *   **Vérifie le système de fichiers et les métadonnées (Redémarrage requis) (chkdsk /f):** Performs a scan that may require a restart to fix errors.
    *   **Vérifier la fragmentation du disque dur principal:** Analyzes the fragmentation level of the main drive. If an SSD is detected, it will indicate that defragmentation is not necessary.
    *   **Défragmenter le disque dur principal:** Defragments the main drive if it's not an SSD.
    *   **Vider les dossiers temporaires:** Clears temporary files from `C:\Windows\Temp`, `%TEMP%`, `%LOCALAPPDATA%\Temp`, and `C:\Windows\Prefetch`.
    *   **Nettoyage des fichiers résidus de Windows Update:** Runs `Cleanmgr.exe` to clean up Windows Update files.
    *   **Nettoyage des miniatures:** Runs `Cleanmgr.exe` to clear the thumbnail cache.

5.  **Effectuer une sauvegarde de Windows (créer un point de restauration):**
    *   Creates a system restore point with the description "Point de restauration créé par le script de maintenance."
    *(This functionality relies on the `New-CmRestorePoint` cmdlet, which may require specific Windows components or features to be enabled.)*

6.  **Restaurer à partir d'un point de restauration:**
    *   Lists available system restore points and allows you to select one to restore your system to a previous state.

7.  **Quitter:** Exits the script and restores the original PowerShell execution policy.

## Logging

The script automatically logs its operations. A transcript of the session is saved to a `.log` file in the `$env:TEMP\MyScriptLogs` directory (usually `C:\Users\[YourUserName]\AppData\Local\Temp\MyScriptLogs`). Each log file is named with the date and time of execution (e.g., `yyyy-MM-dd_HH-mm-ss.log`).

## Disclaimer

This script makes changes to your system, including modifying system settings, installing software, and running system repair tools. While it is designed to be helpful, ensure you understand what each option does before using it. The author is not responsible for any damage or data loss that may occur from using this script. **Use at your own risk.** It is always recommended to back up important data before running system maintenance tools.
