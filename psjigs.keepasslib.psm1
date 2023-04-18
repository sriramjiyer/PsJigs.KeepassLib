function Use-Keepass {
    [CmdletBinding()]
    param ()
    'KeePass.exe', 'KeePass.XmlSerializers.dll' | ForEach-Object {
        $path = Join-Path -Path $PSScriptRoot -ChildPath 'keepass' | Join-Path -ChildPath $_ -Resolve
        Write-Host $path
        [Reflection.Assembly]::LoadFile($path)
    }
}

function New-KeepassDb {
    [CmdletBinding()]
    param (
        # Keepass kdbx file path
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        # Password as PSCredential, SecureString or clear text
        [Parameter()]
        [AllowNull()]
        [object] $Secret,

        # Key file to be used as part of the composite key
        [Parameter()]
        [AllowNull()]
        [string] $KeyFilePath,

        # Include Windows Account as part of composite key
        [Parameter()]
        [switch] $UseWindowsAccount
    )
    $CompositeKey = New-Object -TypeName KeepassLib.Keys.CompositeKey
    if ( -Not $Secret -and -Not $KeyFilePath -and -Not $UseWindowsAccount ) {
        throw 'At lease one of the following is required Secret, KeyFile or UseWindowsAccount'
    }
    $Pass = if ( -Not $Secret ) {
        $null
    }
    elseif ( $Secret -is [pscredential] ) {
        ConvertFrom-SecureString -SecureString $Secret.Password -AsPlainText
    }
    elseif ( $Secret -is [securestring] ) {
        ConvertFrom-SecureString -SecureString $Secret -AsPlainText
    }
    elseif ( $Secret -is [string] ) {
        $Secret
    }
    else {
        throw "Secret should be null or of type pscredential, securestring or string"
    }
    if ( $null -ne $Pass ) {
        $CompositeKey.AddUserKey( ( New-Object -Type KeypassLib.Keys.KcpPassword( $Pass ) ) )
    }
    if ( $KeyFilePath ) {
        $KeyFile = Get-Item -Path $KeyFilePath -ErrorAction Stop
        $CompositeKey.AddUserKey( ( New-Object -Type KeepassLib.Keys.KcpKeyfile( $KeyFile.FullName ) ) )
    }
    if ( $UseWindowsAccount ) {
        $CompositeKey.AddUserKey( ( New-Object -Type KeepassLib.Keys.KcpUserAccount ) )
    }
}

Use-Keepass