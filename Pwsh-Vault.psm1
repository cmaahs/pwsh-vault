$ModuleSources = @(Get-ChildItem -Path "$(Resolve-Path $PSScriptRoot\bin\)*.ps1" -Recurse -ErrorAction SilentlyContinue)
    foreach( $import in $ModuleSources )
    {
        Try
        {
            . $import.fullname
        }
        Catch
        {
            Write-Error -Message "Failed to import function $($import.fullname): $_"
        }
    }
