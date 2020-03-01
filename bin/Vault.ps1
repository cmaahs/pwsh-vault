Function Get-Vault
{
<#
.Synopsis
    This is a stub function, to STOP auto-complete at Get-Vault, and allow you to type the next character.

.EXAMPLE
    Type Get-Vau{tab} to get to Get-Vault.
    Then Type S{tab} to expand out to Get-VaultSecretFromKeyPath
#>
    [CmdletBinding()]
    Param
    (
    )

    Begin
    {
        $continueProcessing = $true
    }
    Process
    {
        if ( $continueProcessing -eq $true )
        {

        } #continue processing
    }
    End
    {
        if ( $continueProcessing -eq $true )
        {
            Get-Command -Module VaultHttp
        }
    }
}

Function Get-VaultKeyPaths
{
<#
.Synopsis
    List ALL of the secret Key Paths in the Vault.
.DESCRIPTION
    Provides an interface with which to discover ALL of the Secret Key Paths within the Vault.
.EXAMPLE
    Get-VaultKeyPaths
...
...

.EXAMPLE
    Get-VaultKeyPaths | Where-Object { $_.KeyPath -like "*principal*" }

KeyPath
-------

#>
    [Cmdletbinding()]
	Param
    (
        [Parameter(Mandatory=$false,
                    Position = 1)]
        [string]$KeyPath
    )

    Begin
    {
        $continueProcessing = $true
    }

    Process
    {

    }

    End
    {
        if ( $continueProcessing -eq $true )
        {
            Write-Verbose "Environment: $($Environment)"
            $key = Get-Content -Path "~/.vault-token"
            $vault_server = $ENV:VAULT_ADDR
            if ( $key )
            {
                if ( $continueProcessing -eq $true )
                {
                    $keys = @()
                    if ( $KeyPath.Length -gt 0 )
                    {
                        $listPath = "secret/metadata/$($KeyPath)"
                    } else {
                        $listPath = "secret/metadata/"
                    }
                    if ( $continueProcessing -eq $true )
                    {
                        $headers = @{"X-Vault-Token"="$($key)"}
                        $URI = "$($vault_server)/v1/$($listPath)"

                        Write-Debug $headers['X-Vault-Token']
                        Write-Debug $URI
                        $output = Invoke-WebRequest -Uri $URI -Headers $headers -CustomMethod List
                        $jsonData = $output | ConvertFrom-Json

                        #$output =  Invoke-SSHCommand -Command "curl -H `"X-Vault-Token: $($apiKey)`" -X GET https://$($envir[1])$($envir[0])vvault01.$($envir[1]).local:8200/v1/$($listPath)/?list=true" -SessionId $sessionID

                        foreach ( $k in $jsonData.Data.Keys )
                        {
                            #Write-Output $k
                            $item = "" | Select-Object KeyPath
                            if ( $KeyPath.Length -gt 0  )
                            {
                                $item.KeyPath = "$($KeyPath)/$($k)" # $l.Replace("/","")
                            } else {
                                $item.KeyPath = "$($k)" # $l.Replace("/","")
                            }

                            if ( $k.EndsWith("/") )
                            {
                                Write-Verbose "Looking up subkey: $($KeyPath)/$($k)"
                                Write-Progress -Activity "Looking up Sub-Keys" -Status "Looking up subkey: $($KeyPath)/$($k)"
                                Write-Verbose "$($KeyPath)/$($k.Replace('/',''))"
                                $subKeys = Get-VaultKeyPaths -KeyPath "$($KeyPath)/$($k.Replace('/',''))"
                                $keys += $subKeys
                            } else {
                                $keys += $item
                            }
                        }
                    }

                    Write-Output $keys
                } #continue processing
            } else {
                Write-Warning "Unable to read the API Key, please ensure you have authenticated successfully with the vault."
            }
        } #continue processing

    }
}

Function Get-VaultSecretFromKeyPath
{
<#
.Synopsis
    Fetch a specific key path from the vault.

.DESCRIPTION
    Gather the secret from a specific keypath.

.EXAMPLE
    $secret = Get-VaultSecretFromKeyPath /aue01/foreman
    $secret.Secret


.EXAMPLE
    (Get-VaultSecretFromKeyPath -KeyPath /aue01/spacewalk).Secret


.EXAMPLE
    $everything = Get-VaultKeyPaths | Get-VaultSecretFromKeyPath
    ($everything | Where-Object { $_.KeyPath -eq "aue01/spacewalk" }).Secret


#>
    [Cmdletbinding()]
	Param
    (
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position = 0)]
        [string]$KeyPath
        ,
        [Parameter(Mandatory=$false,
                    Position = 2)]
        [switch]$RawOutput
        ,
        [Parameter(Mandatory=$false,
                    Position = 3)]
        [switch]$Flatten

    )

    Begin
    {
        $continueProcessing = $true
        $secrets = @()
        $key = Get-Content -Path "~/.vault-token"
        $vault_server = $ENV:VAULT_ADDR
    }

    Process
    {
        Write-Verbose "Processing KeyPath: $($KeyPath)"
        if ( $continueProcessing -eq $true )
        {
            if ( $key )
            {
                if ( $continueProcessing -eq $true )
                {
                    if ( $KeyPath.StartsWith("/") ) {
                        $KeyPath = $KeyPath.Substring(1)
                    }

                    $header = @{"X-Vault-Token"="$($key)";}
                    $URI = "$($vault_server)/v1/secret/data/$($KeyPath)"

                    $output = Invoke-WebRequest -URI $URI -Headers $header
                    #$output =  Invoke-SSHCommand -Command "curl -H `"X-Vault-Token: $($key)`" -X GET https://$($envir[1])$($envir[0])vvault01.$($envir[1]).local:8200/v1/secret/$($KeyPath)" -SessionId $sessionID

                    if ( $RawOutput -eq $true )
                    {
                        Write-Output $output
                    }
                    $jsonData = $output | ConvertFrom-Json
                    #Write-Output $jsonData.Data
                    if ( $Flatten -eq $true )
                    {
                        $propertyName = ($jsonData.Data.Data | Get-Member | Where-Object { $_.MemberType -eq "NoteProperty" } ).Name
                        foreach ( $pn in $propertyName )
                        {
                            #$kv = "" | Select-Object SecretName, SecretValue
                            #$kv.SecretName = $pn
                            #$kv.SecretValue = $jsonData.Data.($pn)
                            #$item = "" | Select-Object KeyPath,Secret
                            #$item.KeyPath = $KeyPath
                            #$item.Secret = $kv
                            #$secrets += $item
                            $kv = "" | Select-Object KeyPath, SecretName, SecretValue
                            $kv.KeyPath = $KeyPath
                            $kv.SecretName = $pn
                            $kv.SecretValue = $jsonData.Data.Data.($pn)
                            $secrets += $kv

                        }
                    } else {
                        $item = "" | Select-Object KeyPath,Secret
                        $item.KeyPath = $KeyPath
                        $item.Secret = $jsonData.Data.Data
                        $secrets += $item
                    }

                } #continue processing
            } else {
                Write-Warning "Unable to read the API Key, please authenticate to the vault server"
            }
        } #continue processing

    }
    End
    {
        if ( $continueProcessing -eq $true )
        {
            Write-Output $secrets
        } #continue processing
    }
}

