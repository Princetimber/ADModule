<#
.SYNOPSIS
  This function installs a new Active Directory domain controller in Azure or on-premises.
.DESCRIPTION
  This script provides a convenient way to create a new Active Directory domain controller in Azure or on-premises. The script installs the required modules, connects to Azure, retrieves the Safe Mode Administrator Password and Domain Admin Password from the Key Vault, and creates a new Active Directory domain controller. The script also unregisters the secret vault and disconnects from Azure after the domain controller is created.
.PARAMETER DomainName
  The FQDN of the domain to create.
.PARAMETER SiteName
  The name of the site where the domain controller is located. This defaults to the value of 'Default-First-Site-Name'.
.PARAMETER DatabasePath
  The path to the database folder for the domain controller. This defaults to the Windows directory on the system drive.
.PARAMETER LogPath
  The path to the log folder for the domain controller. This defaults to the Windows directory on the system drive.
.PARAMETER SysvolPath
  The path to the Sysvol folder for the domain controller. This defaults to the Windows directory on the system drive.
.PARAMETER KeyVaultName
  The name of the Key Vault that contains the Safe Mode Administrator Password and Domain Admin Password.
.PARAMETER ResourceGroupName
  The name of the resource group where the Key Vault is located.
.PARAMETER SafeModeAdminSecretName
  The name of the secret in the Key Vault that contains the Safe Mode Administrator Password.
.PARAMETER DomainAdminSecretName
  The name of the secret in the Key Vault that contains the Domain Admin Password.
.PARAMETER DomainAdminUser
  The username of the Domain Admin account used to install the domain controller e.g. 'domain\username'.
.PARAMETER Force
  Forces the operation to continue without asking for confirmation.
.NOTES
  File Name      : New-ADDSDomainController.ps1
  Author         : Olamide Olaleye
  Prerequisite   : PowerShell 7.1.3 or later
  Modules        : Microsoft.PowerShell.SecretManagement, az.keyVault
  Windows Features: AD-Domain-Services
  Key Vault      : The Key Vault must be created and the secret must be created in the Key Vault that contains the password for the Safe Mode Administrator Password and Domain Admin Password.
  Registered Vault: The Key Vault is registered as a secret vault using the Register-SecretVault cmdlet.
  Secret Retrieval: The Safe Mode Administrator Password and Domain Admin Password are retrieved from the Key Vault using the Get-Secret cmdlet.
  Online Version:
.LINK
  Specify a URI to a help page, this will show when Get-Help -Online is used.
.EXAMPLE
  New-ADDSDomainController -DomainName 'contoso.com' -KeyVaultName 'mykeyvault' -ResourceGroupName 'myresourcegroup' -SafeModeAdminSecretName 'SafeModeAdminPassword' -DomainAdminSecretName 'DomainAdminPassword' -DomainAdminUser 'contoso\administrator'
  This example creates a new Active Directory domain controller with the specified parameters.
  It assumes that the Key Vault 'mykeyvault' contains the Safe Mode Administrator Password and Domain Admin Password.
  The Domain Admin account is 'contoso\administrator'.
#>

$ErrorActionPreference = "Stop"
$Global:RegisteredSecretVault = $null
$Global:AzureConnection = $null
$PSDefaultParameterValues = @{
  'New-ADDSDomainController:SiteName' = 'Default-First-Site-Name'
  'New-ADDSDomainController:DatabasePath' = "$env:SystemDrive\Windows\"
  'New-ADDSDomainController:LogPath' = "$env:SystemDrive\Windows\NTDS\"
  'New-ADDSDomainController:SysvolPath' = "$env:SystemDrive\Windows\"
  'New-ADDSDomainController:Force' = $true
}
function Install-RequiredModule {
  param(
    [string[]]$Name = @( 'Microsoft.PowerShell.SecretManagement', 'az.keyvault')
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
  [string]$Name = 'AD-Domain-Services'
  if (-not (Get-WindowsFeature -Name $Name | Where-Object { $_.Installed -eq $true })) {
    try {
      install-WindowsFeature -Name $Name -IncludeManagementTools
    }
    catch {
      Write-Error "Failed to install the required module $Name. Please see the error message below.:$_"
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
      Write-Error "Path $_ does not exist"
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
function Get-Vault {
  param(
    [string]$keyVaultName,
    [string]$ResourceGroupName
  )
  Get-AzKeyVault @PSBoundParameters
}
funtion Add-AdminCredential{
  param(
    [string]$DomainAdminUser,
    [string]$DomainAdminSecretName
  )
  [securestring]$DomainAdminPassword = Get-Secret -Name $DomainAdminSecretName -Vault $vaultName
  New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $DomainAdminUser, $DomainAdminPassword
}
function Add-RegisteredSecretVault {
  param(
    [string]$Name = (Get-Vault).VaultName,
    [string]$ModuleName = "az.keyvault",
    [hashtable]$VaultParameters = @{
      AZKVaultName = $Name
      SubscriptionId = (Get-AzContext).Subscription.Id
    }
  )
  if($null -eq $Global:RegisteredSecretVault){
    try {
      Register-SecretVault -Name $Name -ModuleName $ModuleName -VaultParameters $VaultParameters -Confirm:$false
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
function Add-ADDomainController {
  param(
    [string]$DomainName,
    [string]$SiteName = 'Default-First-Site-Name',
    [string]$DatabasePath = "$env:SystemDrive\Windows\",
    [string]$LogPath = "$env:SystemDrive\Windows\NTDS\",
    [string]$SysvolPath = "$env:SystemDrive\Windows\",
    [string]$KeyVaultName,
    [string]$ResourceGroupName,
    [string]$SafeModeAdminSecretName,
    [string]$DomainAdminSecretName,
    [string]$DomainAdminUser
  )
  # set paths
  $DatabasePath = New-EnvPath -Path $DatabasePath -ChildPath 'ntds'
  $LogPath = New-EnvPath -Path $LogPath -ChildPath 'ntds'
  $SysvolPath = New-EnvPath -Path $SysvolPath -ChildPath 'sysvol'
  # install required modules
  Install-RequiredModule
  Install-RequiredADModule
  # connect to azure
  Connect-ToAzure
  # get the vault
  Get-Vault
  Add-RegisteredSecretVault
  # define common parameters
  $commonParams = @{
    DomainName = $DomainName
    SiteName = $SiteName
    DatabasePath = $DatabasePath
    LogPath = $LogPath
    SysvolPath = $SysvolPath
    Force = $true
  }
  # retrieve the safe mode admin password
  $vaultName = (Get-Vault).VaultName
  [securestring]$safeModeAdministratorPassword = Get-Secret -Name $SafeModeAdminSecretName -Vault $vaultName
  $param = $commonParams.Clone()
  $keys = @{
    SafeModeAdministratorPassword = $safeModeAdministratorPassword
  }
  Add-keys -hash $param -keys $keys
  # retrieve the domain admin password
  $credential = Add-AdminCredential
  $param = $commonParams.Clone()
  $keys = @{
    Credential = $credential
  }
  Add-keys -hash $param -keys $keys
  # add the domain controller
  Install-ADDSDomainController @param
}
function New-ADDSDomainController{
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter (Mandatory = $true)][string]$DomainName,
    [Parameter (Mandatory = $false)][string]$SiteName = 'Default-First-Site-Name',
    [Parameter (Mandatory = $false)][string]$DatabasePath = "$env:SystemDrive\Windows\",
    [Parameter (Mandatory = $false)][string]$LogPath = "$env:SystemDrive\Windows\NTDS\",
    [Parameter (Mandatory = $false)][string]$SysvolPath = "$env:SystemDrive\Windows\",
    [Parameter (Mandatory = $true)][string]$KeyVaultName,
    [Parameter (Mandatory = $true)][string]$ResourceGroupName,
    [Parameter (Mandatory = $true)][string]$SafeModeAdminSecretName,
    [Parameter (Mandatory = $true)][string]$DomainAdminSecretName,
    [Parameter (Mandatory = $true)][string]$DomainAdminUser,
    [Parameter (Mandatory = $false)][switch]$Force
  )
  try {
    if($PSCmdlet.ShouldProcess($DomainName,"Add a new domain controller") -or $PSCmdlet.ShouldContinue("Do you want to continue?")){
      Add-ADDomainController @PSBoundParameters
    }
    else{
      Write-Output "Operation cancelled"
    }
  }
  catch {
    Write-Error "Failed to add the domain controller. Please see the error message below.:$_"
  }
  finally {
    if($null -ne $Global:RegisteredSecretVault){
      Unregister-SecretVault -Name (Get-Vault).VaultName -Confirm:$false
      $Global:RegisteredSecretVault = $null
    }
    Disconnect-AzAccount -Confirm:$false
  }
}