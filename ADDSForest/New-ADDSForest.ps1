<#
.SYNOPSIS
  This function installs a new Active Directory domain in Azure or on-premises.
.DESCRIPTION
  This scritp provides a convenient way to create a new Active Directory domain in Azure or on-premises. The script installs the required modules, connects to Azure, retrieves the Safe Mode Administrator Password from the Key Vault, and creates a new Active Directory domain. The script also unregisters the secret vault and disconnects from Azure after the domain is created.
.PARAMETER DomainName
  The FQDN of the domain to create.
.PARAMETER DomainNetBIOSName
  The NetBIOS name of the domain to create.
.PARAMETER DomainMode
  The domain functional level of the domain to create. This defaults to the value of the 'WinThreshold'
.PARAMETER ForestMode
  The forest functional level of the domain to create.This defaults to the value of the 'WinThreshold'.
.PARAMETER DatabasePath
  The path to the directory where the AD DS database is stored. This defaults to the value of '$env:SystemDrive\Windows\'. if the parameter is not specified. I strongly recommend that you use a separate disk for the database.
.PARAMETER LogPath
  The path to the directory where the AD DS log files are stored. This defaults to the value of '$env:SystemDrive\Windows\NTDS\'. if the parameter is not specified. I strongly recommend that you use a separate disk for the log files.
.PARAMETER SysvolPath
  The path to the directory where the AD DS system volume (SYSVOL) is stored. This defaults to the value of '$env:SystemDrive\Windows\'. if the parameter is not specified. I strongly recommend that you use a separate disk for the SYSVOL.
.PARAMETER KeyVaultName
  The name of the Key Vault to use.
.PARAMETER ResourceGroupName
  The name of the resource group to use where the Key Vault is located.
.PARAMETER SecretName
  The name of the secret in the Key Vault that contains the password for the Safe Mode Administrator Password.This defaults to the value of 'safeModeAdministratorPassword'.
  .PARAMETER Force
  This parameter suppresses the confirmation prompt.
.NOTES
  File Name      : New-ADDomain.ps1
  Author         : Olamide Olaleye
  Prerequisite   : PowerShell 7.1.3 or later
  Modules        : Microsoft.PowerShell.SecretManagement, az.keyVault
  Windows Features: AD-Domain-Services
  Key Vault      : The Key Vault must be created and the secret must be created in the Key Vault that contains the password for the Safe Mode Administrator Password.
  Registered Vault: The Key Vault is registered as a secret vault using the Register-SecretVault cmdlet.
  Secret Retrieval: The Safe Mode Administrator Password is retrieved from the Key Vault using the Get-Secret cmdlet.
  Online Version:
  Default Parameters: The default parameters are stored in the DefaultParameters.json file. Ensure that the file is in the same directory as the script.
  Help Version   : 1.0
  Date           : 2024-04-07
  Change History : 2024-04-07 - Initial version
.LINK
  Specify a URI to a help page, this will show when Get-Help -Online is used.
.EXAMPLE
  New-ADDSForest -DomainName "contoso.com" -DomainNetBIOSName "CONTOSO" -DomainMode -ForestMode -DatabasePath "D:\" -LogPath E:\ -SysvolPath "F:\" -KeyVaultName "ContosoKeyVault" -ResourceGroupName "ContosoResourceGroup" -SecretName "safeModeAdministratorPassword"
#>
$ErrorActionPreference = "Stop"
$Global:RegisteredSecretVault = $null
$Global:AzureConnection = $null
$DefaultParameters = Get-Content -Path $PSScriptRoot\DefaultParameters.json | ConvertFrom-Json
$PSDefaultParameterValues = $DefaultParameters.PSDefaultParameterValues
function Install-RequiredModule {
  param(
    [string[]]$Name
  )
  $Name | ForEach-Object {
    if(-not (Get-Module -Name $_ -ListAvailable)){
      try {
        Set-PSResourceRepository -Name PSGallery -Trusted
        Install-PSResource -Name $_ -Repository PSGallery -Scope AllUsers -Confirm:$false
        Write-Output "Module $_ installed successfully"
      }
      catch {
        Write-Error -Message "Failed to install module $_. Please see the error message below.:$_"
      }
    }
    else {
      Write-Output "Module $_ is already installed"
    }
  }
}
function Install-RequiredADModule {
  [string]$Name
  if (-not (Get-WindowsFeature -Name $Name | Where-Object { $_.Installed -eq $true })) {
    try {
      install-WindowsFeature -Name $Name -IncludeManagementTools
    }
    catch {
      throw "Failed to install the required module $ModuleName. Please see the error message below.:$_"
    }
  }
  else {
    Write-Output "Module $ModuleName is already installed"
  }
}
function Add-keys{
  param($hash, $keys)
  $keys.GetEnumerator() | ForEach-Object {
    $hash.Add($_.Key, $_.Value)
  }
}
function New-EnvPath {
  param(
    [string]$Path,
    [string]$ChildPath
  )
  return Join-Path @PSBoundParameters
}
function Test-Paths {
  param(
    [string[]]$Paths 
  )
  $paths | ForEach-Object {
    if (-not (Test-Path -Path $_)) {
      throw "Path $_ does not exist"
    }
  }
}
function Connect-ToAzure {
  if($null -eq $Global:AzureConnection){
    Connect-AzAccount -UseDeviceAuthentication
    $timeout = New-TimeSpan -Seconds 90
    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($stopWatch.Elapsed -lt $timeout) {
      $Global:AzureConnection = (Get-AzContext -ErrorAction SilentlyContinue).Account
      if($Global:AzureConnection){
        break
      }
      Start-Sleep -Seconds 5     
    }
  }
}
function Add-RegisteredSecretVault {
  param(
    [string]$Name,
    [string]$ModuleName,
    [hashtable]$VaultParameters
  )
  if($null -eq $Global:RegisteredSecretVault){
    try {
      Register-SecretVault @PSBoundParameters
      if($Global:RegisteredSecretVault){
        return
      }
    }
    catch {
      Write-Error "Failed to register the secret vault. Please see the error message below.:$_"
    }
  }
  else{
    Write-Output "Secret vault $Name is already registered"
  }
}
function Get-Vault {
  param(
    [string]$keyVaultName,
    [string]$ResourceGroupName
  )
  Get-AzKeyVault @PSBoundParameters
}
function New-ADDSForest {
  param(
    [string]$DomainName,
    [string]$DomainNetBiosName,
    [string]$DomainMode,
    [string]$ForestMode,
    [string]$DatabasePath,
    [string]$LogPath,
    [string]$SysvolPath,
    [string]$KeyVaultName,
    [string]$ResourceGroupName,
    [string]$secretName
  )
  # set the paths
  $LOG_PATH = New-EnvPath -Path $LogPath -ChildPath 'logs'
  $DATABASE_PATH = New-EnvPath -Path $DatabasePath -ChildPath 'ntds'
  $SYSVOL_PATH = New-EnvPath -Path $SysvolPath -ChildPath 'SYSVOL'
  # install required modules
  Install-RequiredModule
  Install-RequiredADModule
  # connect to Azure
  Connect-ToAzure
  # get the vault
  Get-Vault
  Add-RegisteredSecretVault
  # define common parameters
  $commonParams = @{
    InstallDNS = $true
    DomainName = $DomainName
    DomainNetBiosName = $DomainNetBiosName
    DomainMode = $DomainMode
    ForestMode = $ForestMode
    DatabasePath = $DATABASE_PATH
    LogPath = $LOG_PATH
    SysvolPath = $SYSVOL_PATH
    Force = $true
  }
  # retrieve the safe mode administrator password
  $vaultName = (Get-Vault).VaultName
  $safeModeAdministratorPassword = Get-Secret -Name $secretName -Vault $vaultName
  $param = $commonParams.Clone()
  $keys = @{
    SafeModeAdministratorPassword = $safeModeAdministratorPassword
  }
  Add-keys -hash $param -keys $keys
  # create the new AD Forest
  Install-ADDSForest @param
}
function New-ADForest {
  [CmdletBinding(SupportsShouldProcess  = $true)]
  param(
    [Parameter(Mandatory = $true)]
    [string]$DomainName,
    [Parameter(Mandatory = $true)]
    [string]$DomainNetBiosName,
    [Parameter(Mandatory = $false)]
    [string]$DomainMode,
    [Parameter(Mandatory = $false)]
    [string]$ForestMode,
    [Parameter(Mandatory = $false)]
    [string]$DatabasePath,
    [Parameter(Mandatory = $false)]
    [string]$LogPath,
    [Parameter(Mandatory = $false)]
    [string]$SysvolPath,
    [Parameter(Mandatory = $true)]
    [string]$KeyVaultName,
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    [Parameter(Mandatory = $true)]
    [string]$secretName,
    [Parameter(Mandatory = $false)]
    [switch]$Force
  )
  try {
    if($PSCmdlet.ShouldProcess($DomainName,"Create a new Active Directory Forest") -or $PSCmdlet.ShouldContinue("Do you want to continue?")) {
      New-ADDSForest @PSBoundParameters
    }
    else{
      Write-Output "Operation cancelled"
    }
  }
  catch {
    throw "Failed to create the new AD Forest. Please see the error message below.:$_"
  }
  finally {
    # unregister the secret vault
    if($null -ne $Global:RegisteredSecretVault){
      Unregister-SecretVault -Name (Get-Vault).VaultName -Confirm:$false
      $Global:RegisteredSecretVault = $null
    }
    Disconnect-AzAccount -Confirm:$false
  }
}