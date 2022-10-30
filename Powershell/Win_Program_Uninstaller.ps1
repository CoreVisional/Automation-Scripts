<#
Author: Alex
Created At: 03/08/2022

Generate a list of programs installed found in REGISTRY EDITOR.
This script will prompt you to select the program you wish to uninstall.

NOTE: This script only works on Windows machine (Duh).
#>



# Open an elevated Powershell session
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){   
    $Arguments = "-NoExit -ExecutionPolicy Bypass & '" + $MyInvocation.mycommand.definition + "'"
    Start-Process "$PSHome\powershell.exe" -Verb runAs -ArgumentList $Arguments
    break
}



# Making sure that the user input for selected item is in integer form
function Validate-Input {
    param([Parameter(Mandatory=$true)][String]$Prompt)

    $Number = 0

    while ($true) {
        $IsIntegerNum = [int]::TryParse((Read-Host $Prompt), [ref]$Number)
        
        if (-Not $IsIntegerNum) {
            Write-Host "`nInput must be an integer..."
        }
        else {
            return $Number
        }
    }
}


function Ask-YesNo {
    param([Parameter(Mandatory)][String]$YesNoQuestion)

    $ChoiceYes = @("yes", 'y')
    $ChoiceNo = @("no", 'n')

    While ($true) {
        $UserChoice = (Read-Host -Prompt $YesNoQuestion).ToLower()

        if ($ChoiceYes -contains $UserChoice) {
            return $true
        }
        elseif ($ChoiceNo -contains $UserChoice) {
            return $false
        }
        else {
            Write-Host "`nInvalid Input. Try Again." -ForegroundColor Red
        }
    }
}


function Get-InstalledApps {
    param(
        [Parameter(ValueFromPipeline=$true)]
        [string[]]$ComputerName = $env:COMPUTERNAME
    )
    
    $Selection = 0  # Indicate the selected software to be uninstalled
    $ItemNumber = 0 # Indicate the number of installed software
    $ProgramInfo = @()  # Store the information of the software needed to be uninstalled

    if (!([Diagnostics.Process]::GetCurrentProcess().Path -match '\\syswow64\\')) {

        $32BitProgramsList = "\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $64BitProgramsList = "\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"

        $programsList = @(
        if (Test-Path "HKLM:$32BitProgramsList") {Get-ChildItem "HKLM:$32BitProgramsList"}
        if (Test-Path "HKLM:$64BitProgramsList") {Get-ChildItem "HKLM:$64BitProgramsList"}
        if (Test-Path "HKCU:$32BitProgramsList") {Get-ChildItem "HKCU:$32BitProgramsList"}
        if (Test-Path "HKCU:$64BitProgramsList") {Get-ChildItem "HKCU:$64BitProgramsList"}
        ) |
        ForEach-Object {Get-ItemProperty $_.PSPath} |
        Where-Object {$_.DisplayName -and $_.UninstallString} | 
        Sort-Object DisplayName |
        Select-Object DisplayName, DisplayVersion, InstallDate, QuietUninstallString, UninstallString


        foreach ($program in $programsList) {
            $ItemNumber++
            [PSCustomObject]@{
                ItemNumber = $ItemNumber
                DisplayName = $program.DisplayName
                DisplayVersion = $program.DisplayVersion
                InstallDate = (&{if ($program.InstallDate -ne $null) {$program.InstallDate} else {'-'}})
                QuietUninstallString = (&{if ($program.QuietUninstallString -ne $null) {$program.QuietUninstallString} else {'-'}})
                UninstallString = $program.UninstallString
            }
        }
    }
}


function Select-Item {
    param([Parameter()][string[]]$PropertyToDisplay,
    [Parameter()][object[]]$ProgramsList)

    $Counter = 1

    foreach ($App in $ProgramsList) {
        Write-Host "$Counter. $($App.$PropertyToDisplay)"
        $Counter++
    }

    [int]$Selection = $(Validate-Input "`nSelect Item Number")
    $ProgramsList[$Selection - 1]
}


function Uninstall-Program {
    $AllSoftware = Get-InstalledApps
    $SelectedApp = Select-Item -PropertyToDisplay DisplayName -ProgramsList $AllSoftware

    # Print out details of selected program before uninstalling it
    Write-Output $SelectedApp
    
    # Get the name of the program
    $AppName = $SelectedApp.DisplayName


    if ($SelectedApp) {

        $Response = $(Ask-YesNo "`nAre you sure you want to uninstall $AppName ?  Yes[Y] No[N]")
        
        if ($Response -eq $false) {
            [Environment]::Exit(0)
        }
        else {
            Start-Process powershell.exe -WindowStyle Hidden -Wait -NoNewWindow -Args @('/c', $SelectedApp.UninstallString)
            [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.VisualBasic") > $null
            [Microsoft.VisualBasic.Interaction]::MsgBox("Successfully uninstall $AppName from the computer!", "OKOnly,SystemModal,Information", "Success") > $null
        }        
    }
}


function main {

    while ($true) {
        
        Uninstall-Program

        $RerunScript = $(Ask-YesNo "`nRun this script again? Yes[Y] No[N] (Default is N)")

        if (($RerunScript -eq $false) -or (!$RerunScript)) {
            Write-Host "`nExiting script..."
            [Environment]::Exit(0)
        }
    }
}


main

