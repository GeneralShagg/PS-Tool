# Vérifier la version de PowerShell
$PSVersion = $PSVersionTable.PSVersion
if ($PSVersion.Major -lt 7) {
    Write-Host "Ce script requiert PowerShell 7. Veuillez le lancer avec PowerShell 7." -ForegroundColor Red
    Exit
}

# Vérifier les droits d'administrateur et redémarrer avec PowerShell 7 si nécessaire
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Redémarrage en tant qu'administrateur avec PowerShell 7..."
    Start-Process -FilePath "C:\Program Files\PowerShell\7\pwsh.exe" -ArgumentList "-NoProfile -ExecutionPolicy RemoteSigned -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# Sauvegarder l'exécution policy actuelle
$originalExecutionPolicy = Get-ExecutionPolicy

# Vérification de l'état d'exécution des scripts
$currentExecutionPolicy = Get-ExecutionPolicy
Write-Host "Vérification de l'état d'exécution des scripts..."
Write-Host "L'état d'exécution des scripts actuel est : " -NoNewline
Write-Host "$currentExecutionPolicy" -ForegroundColor Yellow
Start-Sleep -Seconds 2

# 2. Vérifier l'exécution de Script non signés
if ($currentExecutionPolicy -ne "RemoteSigned") {
    Write-Host "Changement de la politique d'exécution à " -NoNewline
    Write-Host "RemoteSigned" -ForegroundColor Yellow -NoNewline
    Write-Host "..."
    Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
    Start-Sleep -Seconds 2
}


# 3. Ajouter un module de logs
# Nouveau chemin universel
$logPath = Join-Path $env:TEMP "MyScriptLogs"

# Assurez-vous que le dossier existe, sinon le créez
if (-not (Test-Path -Path $logPath -PathType Container)) {
    New-Item -Path $logPath -ItemType Directory
}
$LogFileName = "$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory | Out-Null
}
Start-Transcript -Path (Join-Path -Path $LogPath -ChildPath $LogFileName)

# 6. Vérifier si Winget est installé et fonctionnel
if (Get-Command -Name winget -ErrorAction SilentlyContinue) {
    try {
        $wingetInfo = winget --info 2>&1 | Out-String
        Write-Host "Winget est installé et fonctionnel." -ForegroundColor Green
    } catch {
        Write-Host "Winget est installé mais ne fonctionne pas correctement." -ForegroundColor Red
    }
    Start-Sleep -Seconds 3
} else {
    Write-Host "Installation de Winget..."
    Start-Process -FilePath "https://aka.ms/getwinget" -Wait
    Start-Sleep -Seconds 3
}

# 6.1 Vérifier et installer le module PSWindowsUpdate si nécessaire
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Write-Host "Installation du module PSWindowsUpdate..."
    Install-Module -Name PSWindowsUpdate -Force -Confirm:$false
    Import-Module PSWindowsUpdate
} else {
    Write-Host "Le module PSWindowsUpdate est déjà installé." -ForegroundColor Green
}

# 7. Créer un menu
$choice = 0
while ($choice -ne 6) {
    Clear-Host
    Write-Host "MENU DE SÉLECTION" -ForegroundColor Green
    Write-Host "1. Scan et réparation de Windows"
    Write-Host "2. Effectuer la mise à jour des applications avec winget"
    Write-Host "3. Effectuer les mises à jour Windows Update"
    Write-Host "4. Défragmentation et optimisation du disque dur principal"
    Write-Host "5. Effectuer une sauvegarde de Windows (créer un point de restauration)"
    Write-Host "6. Restaurer à partir d'un point de restauration"
    Write-Host "7. Quitter"
    $choice = Read-Host "Entrez le numéro de votre choix"

    switch ($choice) {
        1 {
            # Code pour la première option
            Write-Host "Option 1 sélectionnée. Sous-menu Scan et réparation de Windows."
            $subChoice = 0
            while ($subChoice -ne 4) {
                Clear-Host
                Write-Host "SOUS-MENU SCAN ET RÉPARATION DE WINDOWS" -ForegroundColor Cyan
                Write-Host "1. Scan et réparation des fichiers Windows (sfc /scannow)"
                Write-Host "2. Scan du magasin Windows (DISM /Online /Cleanup-Image /ScanHealth et /CheckHealth)"
                Write-Host "3. Réparation du magasin Windows (DISM /Online /Cleanup-Image /RestoreHealth)"
                Write-Host "4. Retour au menu principal"
                $subChoice = Read-Host "Entrez le numéro de votre choix"

                switch ($subChoice) {
                    1 {
                        Write-Host "Lancement de sfc /scannow..."
                        Start-Process powershell -ArgumentList "sfc /scannow" -Verb RunAs -Wait
                    }
                    2 {
                        Write-Host "Lancement de DISM /Online /Cleanup-Image /ScanHealth..."
                        Start-Process powershell -ArgumentList "DISM /Online /Cleanup-Image /ScanHealth" -Verb RunAs -Wait
                        Write-Host "Lancement de DISM /Online /Cleanup-Image /CheckHealth..."
                        Start-Process powershell -ArgumentList "DISM /Online /Cleanup-Image /CheckHealth" -Verb RunAs -Wait
                    }
                    3 {
                        Write-Host "Lancement de DISM /Online /Cleanup-Image /RestoreHealth..."
                        Start-Process powershell -ArgumentList "DISM /Online /Cleanup-Image /RestoreHealth" -Verb RunAs -Wait
                    }
                    4 {
                        Write-Host "Retour au menu principal."
                    }
                    default {
                        Write-Host "Choix invalide, veuillez sélectionner une option valide."
                    }
                }
            }
        }
        2 {
            Write-Host "Option 2 sélectionnée. Sous-menu Mise à jour avec Winget."
            $subChoice = 0
            while ($subChoice -ne 4) {
                Clear-Host
                Write-Host "SOUS-MENU MISE À JOUR AVEC WINGET" -ForegroundColor Cyan
                Write-Host "1. Afficher la liste des mises à jour disponibles"
                Write-Host "2. Mettre une application à jour"
                Write-Host "3. Mettre toutes les applications à jour"
                Write-Host "4. Retour au menu principal"
                $subChoice = Read-Host "Entrez le numéro de votre choix"

                switch ($subChoice) {
                    1 {
                        Write-Host "Affichage des mises à jour disponibles..."
                        winget upgrade
                    }
                    2 {
                        Write-Host "Mises à jour disponibles :"
                        winget upgrade
                        $appName = Read-Host "Entrez le nom de l'application à mettre à jour"
                        Write-Host "Mise à jour de l'application $appName..."
                        winget upgrade $appName
                    }
                    3 {
                        Write-Host "Mise à jour de toutes les applications..."
                        Start-Sleep -Seconds 2
                    
                        # Sauvegarder le registre avec PowerShell
                        $backupPath = Join-Path $env:USERPROFILE "RegistryBackup.reg"
                        Get-Item -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion" | ForEach-Object {
                            $_.PSPath
                        } | Export-RegFile -Path $backupPath
                    
                        # Créer le chemin du registre s'il n'existe pas
                        $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\WindowsStore"
                        if (-not (Test-Path $registryPath)) {
                            New-Item -Path $registryPath -Force
                        }
                    
                        # Définir l'option d'acceptation de l'EULA à true dans le registre
                        Set-ItemProperty -Path $registryPath -Name "AcceptEULA" -Value "1"
                    
                        # Lancer une nouvelle fenêtre PowerShell avec la commande winget upgrade
                        $process = Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command winget upgrade --all --include-unknown" -PassThru -Wait
                    
                        Write-Host "Mises à jour terminées. Vérification des échecs..."
                        Start-Sleep -Seconds 2
                    
                        # Ajout du code pour vérifier les échecs de mise à jour
                        $failedUpdates = winget upgrade --all --include-unknown | Where-Object { $_.Status -ne 'OK' }
                    
                        if ($failedUpdates.Count -eq 0) {
                            Write-Host "Toutes les mises à jour ont été effectuées avec succès."
                        } else {
                            Write-Host "Certaines mises à jour ont échoué. Voici les détails :"
                            Start-Sleep -Seconds 2
                            $failedUpdates | ForEach-Object {
                                Write-Host "Application: $($_.PackageFullName)"
                                Write-Host "État: $($_.Status)"
                                Write-Host "------------------------"
                                Start-Sleep -Seconds 1
                            }
                        }
                    
                        Start-Sleep -Seconds 2
                    }                                              
                    4 {
                        Write-Host "Retour au menu principal."
                    }
                    default {
                        Write-Host "Choix invalide, veuillez sélectionner une option valide."
                    }
                }
            }
        }
        3 {
            Write-Host "Option 3 sélectionnée. Sous-menu Mises à jour Windows Update."
            $subChoice = 0
            while ($subChoice -ne 5) {
                Clear-Host
                Write-Host "SOUS-MENU MISES À JOUR WINDOWS UPDATE" -ForegroundColor Cyan
                Write-Host "1. Afficher les mises à jour de sécurité disponibles"
                Write-Host "2. Afficher les mises à jour optionnelles disponibles"
                Write-Host "3. Effectuer toutes les mises à jour de sécurité"
                Write-Host "4. Effectuer toutes les mises à jour optionnelles"
                Write-Host "5. Retour au menu principal"
                $subChoice = Read-Host "Entrez le numéro de votre choix"

                switch ($subChoice) {
                    1 {
                        Write-Host "Affichage des mises à jour de sécurité disponibles..."
                        Get-WindowsUpdate -Category "Security Updates"
                    }
                    2 {
                        Write-Host "Affichage des mises à jour optionne0lles disponibles..."
                        Get-WindowsUpdate -Category "Updates"
                    }
                    3 {
                        Write-Host "Installation de toutes les mises à jour de sécurité disponibles..."
                        Install-WindowsUpdate -Category "Security Updates" -AcceptAll -AutoReboot
                    }
                    4 {
                        Write-Host "Installation de toutes les mises à jour optionnelles disponibles..."
                        Install-WindowsUpdate -Category "Updates" -AcceptAll -AutoReboot
                    }
                    5 {
                        Write-Host "Retour au menu principal."
                    }
                    default {
                        Write-Host "Choix invalide, veuillez sélectionner une option valide."
                    }
                }
            }
        }
        4 {
            # Code pour la quatrième option
            Write-Host "Option 4 sélectionnée. Sous-menu Défragmentation et optimisation du disque dur principal."
            $subChoice = 0
            while ($subChoice -ne 9) {
                Clear-Host
                Write-Host "SOUS-MENU DÉFRAGMENTATION ET OPTIMISATION DU DISQUE DUR PRINCIPAL" -ForegroundColor Cyan
                Write-Host "1. Vérifications des erreurs du disque dur Principal"
                Write-Host "2. Vérifie le système de fichiers et les métadonnées du système de fichiers (Redémarrage non requis) (chkdsk /scan)"
                Write-Host "3. Vérifie le système de fichiers et les métadonnées du système de fichiers (Redémarrage requis) (chkdsk /f)"
                Write-Host "4. Vérifier la fragmentation du disque dur principal (si SSD, dire que ce n'est pas nécessaire)"
                Write-Host "5. Défragmenter le disque dur principal (si SSD, empêcher la défragmentation)"
                Write-Host "6. Vider les dossiers temporaires (C:\Windows\Temp, C:\Users\GENERA~1\AppData\Local\Temp, C:\Windows\Prefetch)"
                Write-Host "7. Nettoyage des fichiers résidus de Windows Update"
                Write-Host "8. Nettoyage des miniatures"
                Write-Host "9. Retour au menu principal"
                $subChoice = Read-Host "Entrez le numéro de votre choix"

                switch ($subChoice) {
                    1 {
                        Write-Host "Vérifications des erreurs du disque dur Principal..."
                        chkdsk C: /scan
                        Start-Sleep -Seconds 3
                    }
                    2 {
                        Write-Host "Vérifie le système de fichiers et les métadonnées du système de fichiers (Redémarrage non requis)..."
                        chkdsk C: /scan
                        Start-Sleep -Seconds 3
                    }
                    3 {
                        Write-Host "Vérifie le système de fichiers et les métadonnées du système de fichiers (Redémarrage requis)..."
                        chkdsk C: /f
                        Start-Sleep -Seconds 3
                    }
                    4 {
                        # Vérifier la fragmentation du disque dur principal (si SSD, dire que ce n'est pas nécessaire)
                        $diskInfo = Get-PhysicalDisk | Where-Object MediaType -eq "SSD"

                        if ($diskInfo) {
                            Write-Host "Le disque dur principal est un SSD. La défragmentation n'est pas nécessaire."
                            Start-Sleep -Seconds 3
                        } else {
                            Write-Host "Vérification de la fragmentation du disque dur principal..."
                            Start-Sleep -Seconds 3
                            $defragReport = Optimize-Volume -DriveLetter C -Analyze -Verbose

                            # Analyser le rapport de défragmentation
                            if ($defragReport -match "No optimization is needed") {
                                Write-Host "Le disque dur principal n'a pas besoin d'être défragmenté."
                            } else {
                                Write-Host "Le disque dur principal peut bénéficier d'une défragmentation."
                                Write-Host "Rapport de défragmentation :"
                                Write-Host $defragReport
                            }

                            Start-Sleep -Seconds 3
                        }
                    }
                    5 {
                        # Défragmenter le disque dur principal (si SSD, empêcher la défragmentation)
                        $diskInfo = Get-PhysicalDisk | Where-Object MediaType -eq "SSD"

                        if ($diskInfo) {
                            Write-Host "Le disque dur principal est un SSD. La défragmentation n'est pas nécessaire."
                            Start-Sleep -Seconds 3
                        } else {
                            Write-Host "Défragmentation du disque dur principal en cours..."
                            Start-Sleep -Seconds 3
                            Optimize-Volume -DriveLetter C -Defrag -Verbose
                            Write-Host "Défragmentation terminée."
                            Start-Sleep -Seconds 3
                        }
                    }
                    6 {
                        # Vider les dossiers temporaires
                        Write-Host "Vidage des dossiers temporaires en cours..."

                        # Chemins des dossiers temporaires
                        $tempFolders = @("$env:TEMP", "C:\Windows\Temp", "$env:LOCALAPPDATA\Temp", "C:\Windows\Prefetch")

                        $sizeBefore = 0

                        foreach ($tempFolder in $tempFolders) {
                            if (Test-Path $tempFolder) {
                                # Calculer la taille totale avant la suppression
                                $sizeBefore += (Get-ChildItem $tempFolder -File -Recurse | Measure-Object -Property Length -Sum).Sum

                                # Supprimer tous les fichiers dans le dossier temporaire
                                Remove-Item -Path "$tempFolder\*" -Force -Recurse -ErrorAction SilentlyContinue
                                Write-Host "Dossier temporaire $tempFolder vidé."
                            } else {
                                Write-Host "Le dossier temporaire $tempFolder n'existe pas."
                            }
                        }

                        $sizeAfter = 0

                        foreach ($tempFolder in $tempFolders) {
                            if (Test-Path $tempFolder) {
                                # Calculer la taille totale après la suppression
                                $sizeAfter += (Get-ChildItem $tempFolder -File -Recurse | Measure-Object -Property Length -Sum).Sum
                            }
                        }

                        $sizeDeleted = $sizeBefore - $sizeAfter

                        Write-Host "$sizeDeleted octets de fichiers temporaires supprimés."
                        Write-Host "Vidage des dossiers temporaires terminé."
                        Start-Sleep -Seconds 3
                    }
                    7 {
                        # Nettoyage des fichiers résidus de Windows Update
                        Write-Host "Nettoyage des fichiers résidus de Windows Update en cours..."

                        # Exécute la commande Cleanmgr.exe avec les options pour nettoyer les fichiers Windows Update
                        try {
                            Start-Process -FilePath "Cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait -PassThru
                            Write-Host "Nettoyage des fichiers résidus de Windows Update terminé."
                        } catch {
                            Write-Host "Une erreur s'est produite lors du nettoyage des fichiers résidus de Windows Update." -ForegroundColor Red
                        }

                        Start-Sleep -Seconds 3
                    }
                    8 {
                        # Nettoyage des miniatures
                        Write-Host "Nettoyage des miniatures en cours..."

                        # Exécute la commande Cleanmgr.exe avec les options pour nettoyer les miniatures
                        try {
                            Start-Process -FilePath "Cleanmgr.exe" -ArgumentList "/sagerun:2" -Wait -PassThru
                            Write-Host "Nettoyage des miniatures terminé."
                        } catch {
                            Write-Host "Une erreur s'est produite lors du nettoyage des miniatures." -ForegroundColor Red
                        }

                        Start-Sleep -Seconds 3
                    }
                    9 {
                        Write-Host "Retour au menu principal."
                    }
                    default {
                        Write-Host "Choix invalide, veuillez sélectionner une option valide."
                        Start-Sleep -Seconds 3
                    }
                }
            }
        } 
        5 {
            # Effectuer une sauvegarde de Windows (créer un point de restauration)
            Write-Host "Effectuer une sauvegarde de Windows (créer un point de restauration)..."

            try {
                # Créer un point de restauration avec une description
                $description = "Point de restauration créé par le script de maintenance."
                New-CmRestorePoint -Description $description
                Write-Host "Sauvegarde de Windows (point de restauration) créée avec succès."
            } catch {
                $errorMessage = $_.Exception.Message
                Write-Host "Erreur lors de la création de la sauvegarde de Windows (point de restauration): $errorMessage" -ForegroundColor Red
            }

            Start-Sleep -Seconds 3
        }


        6 {
            # Restaurer à partir d'un point de restauration
            Write-Host "Restaurer à partir d'un point de restauration..."
            try {
                # Afficher la liste des points de restauration disponibles
                $restorePoints = Get-ComputerRestorePoint
                if ($restorePoints) {
                    Write-Host "Liste des points de restauration disponibles:"
                    $restorePoints | ForEach-Object {
                        Write-Host "$($_.SequenceNumber): $($_.Description)"
                    }

                    # Demander à l'utilisateur de choisir un point de restauration
                    $restoreChoice = Read-Host "Entrez le numéro du point de restauration que vous souhaitez restaurer"

                    # Restaurer à partir du point de restauration choisi
                    Restore-Computer -RestorePoint $restoreChoice
                    Write-Host "Restauration à partir du point de restauration réussie."
                } else {
                    Write-Host "Aucun point de restauration disponible." -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Erreur lors de la restauration à partir du point de restauration." -ForegroundColor Red
            }

            Start-Sleep -Seconds 3
        }
        7 {
            # Restaurer l'exécution policy à la fin du script
            Write-Host "Restauration de l'exécution policy à son état par défaut..."
            Set-ExecutionPolicy $originalExecutionPolicy -Scope CurrentUser -Force

            # Arrêt de la transcription
            Stop-Transcript

            # Quitter le script
            Write-Host "Quitter le script."
            Exit
        }
        default {
            Write-Host "Choix invalide, veuillez sélectionner une option valide."
        }
    }
}s
