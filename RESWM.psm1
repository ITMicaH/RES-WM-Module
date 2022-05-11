#Requires -Version 5

. "$PSScriptRoot\RESWM-Classes.ps1"

#region helper functions

<#
.Synopsis
   Check if cache location is still reachable
#>
function Test-CacheConnection
{
    [CmdletBinding()]
    Param()
    If ($Drive = Get-PSDrive WMCache)
    {
        $Server = $Drive.Root.Split('\')[2]
        If ($Server -ne 'localhost')
        {
            Write-Verbose "Checking cache connection to relayserver..."
            foreach ($Time in (1..4))
            {
                If ([System.Net.Sockets.TcpClient]::new($Server, 445).Connected)
                {
                    If (!(Test-Path wmcache:\))
                    {
                        $Params = @{
                            Server = $Server
                        }
                        If ($Drive.Credential.UserName)
                        {
                            $Params.Add('Credential',$Drive.Credential)
                        }
                        Write-Verbose "Reconnecting to relayserver $($Server.Split('.')[0])..."
                        Connect-RESWMRelayServer @Params
                    }
                    Write-Verbose "RelayServer connection active."
                    return
                }
                else
                {
                    sleep -Milliseconds 3
                }
            }
            Write-Warning "Connection to relayserver $($Server.Split('.')[0]) is not active."
            If ($RelayServers)
            {
                foreach ($RelayServer in $RelayServers.where({$_ -ne $Server}))
                {
                    Write-Verbose "Attempting to connect to relayserver $RelayServer..."
                    $Ping = Get-WmiObject -Class Win32_PingStatus -Filter "(Address='$RelayServer') and timeout=1000" -Property StatusCode
                    If ($Ping.StatusCode -eq 0)
                    {
                        $Params = @{
                            Server = $RelayServer
                        }
                        If ($Drive.Credential.UserName)
                        {
                            $Params.Add('Credential',$Drive.Credential)
                        }
                        Connect-RESWMRelayServer @Params
                        Write-Verbose "RelayServer connection active."
                        return
                    }
                }
            }
            $Params = @{
                Message = "Unable to reconnect to RES ONE Workspace environment."
                Category = 'ConnectionError'
                TargetObject = $Server
                RecommendedAction = "Check relayservers."
                ErrorAction = 'Stop'
            }
            Write-Error @Params
        }
    }
    else
    {
        Write-Error "Not connected to RES ONE Workspace relayserver" -Category ConnectionError -RecommendedAction "Run command Connect-RESWMRelayServer"
    }
}

<#
.Synopsis
   Get a RES WM object from a cache xml
.DESCRIPTION
   Get a RES WM object from a cache xml
.EXAMPLE
   Get-RESWMObject -Source Objects\apps.xml -Type application -Filter "enabled = 'yes'"
.EXAMPLE
   Get-RESWMObject -Source Objects\apps.xml -Type application -User CONTOSO\User001
#>
function Get-RESWMObject
{
    [CmdletBinding(DefaultParameterSetName='Filter')]
    [OutputType([XmlNode])]
    Param
    (
        # Source XML file relative to cache folder
        [Parameter(Mandatory=$true)]
        [string]
        $Source,

        # Type of the object
        [Parameter(Mandatory=$true)]
        [string]
        $Type,

        # Filter using Xpath
        [Parameter(ParameterSetName='Filter')]
        [string]
        $Filter,

        # Filter on user
        [Parameter(ParameterSetName='User')]
        [RESWMUser]
        $User
    )
    
    Test-CacheConnection
    $SubFolder = Get-ChildItem WMCache: | sort LastWriteTime | select -Last 1 -ExpandProperty Name
    [xml]$XML = (Get-Content WMCache:\$SubFolder\$Source).Trim() # Trim counters empty (Description) node issue
    $FullFilter = ''
    If ($PSBoundParameters['Filter'])
    {
        $Filters = $Filter -split '\b(and|or)\b'
        $FullFilterArray = New-Object System.Collections.ArrayList
        Foreach ($Filter in $Filters)
        {
            # Make filter case-insensitive Xpath 1.0 style
            if ($Filter -match '^(and|or)$')
            {
                $null = $FullFilterArray.Add($Filter)
            }
            else
            {
                $Property = "translate($($Filter.Split('=').Trim()[0]),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')"
                $Value = $Filter.Split('=').Trim()[1].ToLower()              

                If ($Value -match "^'(\*)?([^\*]+)(\*)?'$")
                {
                    # Convert wildcards to Xpath 1.0 queries
                    switch (($Matches.Keys | measure -Sum).Sum)
                    {
                        2 {$null = $FullFilterArray.Add("$Property=$Value")}
                        3 {$null = $FullFilterArray.Add("('$($Matches[2])'=substring($Property,string-length($($Filter.Split('=').Trim()[0]))-string-length('$($Matches[2])')+1))")}
                        5 {$null = $FullFilterArray.Add("(starts-with($Property,'$($Matches[2])'))")}
                        6 {$null = $FullFilterArray.Add("(contains($Property,'$($Matches[2])'))")}
                    }
                }
                elseif ($Value -match '\*')
                {
                    Write-Error 'Wildcards are only supported on the start and/or at end of the string' -Category InvalidArgument -ErrorAction Stop
                }
                else
                {
                    $FullFilterArray = $Filter
                }
            }
        }
        $FullFilter = $FullFilterArray -join ' '
    }
    ElseIf ($PSBoundParameters['User'])
    {
        switch ($Type)
        {
            application  {
                $GroupCheck = $User.MemberOf.ForEach({"*/*/*/grouplist/group='$_'"}) -join ' or '
                $NotGroupCheck = '(not(' + ($User.MemberOf.ForEach({"*/*/*/notgrouplist/group='$_'"}) -join ' or ') + '))'
                $UserCheck = "*/*/*/grouplist/group='$User'"
                $NotUserCheck = "(not(*/*/*/notgrouplist/group='$User'))"
                $Everyone = "*/*/*/accesstype='all'"
                $FullFilter = "(*/*/*/*/ou = '$($User.ParentOU)' or $Everyone or $UserCheck or $GroupCheck) and ($NotGroupCheck or $NotUserCheck) and (not(system = 'yes'))"
            }
            Default      {
                $GroupCheck = $User.MemberOf.ForEach({"(*/*/*/access[object='$_' and (not(options='notingroup'))])"}) -join ' or '
                $UserCheck = "(*/*/*/access[object='$User' and (not(options='notuser'))])"
                $Everyone = "*/*/*/access/type='global'"
                $FullFilter = "(*/*/*/*/ou = '$($User.ParentOU)' or $Everyone or $UserCheck or $GroupCheck) and (not(system = 'yes'))"
            }
        }
    }
    ElseIf ($Type -ne 'securityrole')
    {
        $FullFilter = "(not(system = 'yes'))"
    }
    #If ($Type -eq 'application')
    #{
        return (Select-Xml -Xml $XML -XPath "/*/*[$FullFilter]").Node
    #}
    #else
    #{
    #    Select-Xml -Xml $XML -XPath "/*/*[$FullFilter]" | select -ExpandProperty Node | Set-CapitalizedXMLValues -PassThru
    #}
}

# Make sure all values in XML have a capitilized first letter
function Set-CapitalizedXMLValues
{
    [CmdletBinding()]
    [OutputType([XmlNode])]
    Param(
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true)]
        [XmlNode]
        $XmlNode,

        [switch]
        $PassThru
    )
    Process 
    {
        If (!$PSBoundParameters['XmlNode'])
        {
            return
        }
        $Properties = (Get-Member -InputObject $XmlNode -MemberType Property).Name
        foreach ($Property in $Properties)
        {
            If ($XmlNode.$Property -is [XmlElement])
            {
                Set-CapitalizedXMLValues -XmlNode $XmlNode.$Property
            }
            elseif ($XmlNode.$Property -and $XmlNode.$Property -is [string])
            {
                $XmlNode.$Property = $XmlNode.$Property.Substring(0,1).ToUpper() + $XmlNode.$Property.Substring(1)
            }
        }
        If ($PSBoundParameters['PassThru'])
        {
            return $XmlNode
        }
    }
}

# Convert content of a reg file to a registry object
function Get-WMREGFile
{
    Param ([string]$File,[switch]$ShowContent,[string]$SaveFile)

    $RegContent = [regex]::split($File,'(.{2})').where({$_}).forEach({[char]([convert]::toint16($_,16))}) -join '' -split "`r`n"
    If ($PSBoundParameters['ShowContent'])
    {
        return $RegContent
    }
    If ($PSBoundParameters['SaveFile'])
    {
        return $RegContent | Set-Content -Path $SaveFile -PassThru
    }
    $RegType = 'Policy'
    try{
        switch -Regex ($RegContent)
        {
            ';<PFNAME>(.+)</PFNAME>' {
                $RegType = 'Registry'
                $Description = $Matches[1]
            }
            ';<PFDESC>(.+)</PFDESC>' {
                $RegType = 'Registry'
                If ($Matches[1] -ne ' ')
                {
                    $Description = $Matches[1]
                }
            }
            '\[(?<Key>.+)\]' {
                $Key = $Matches.Key
            }
            '"?(?<Name>[^"]+)"?=((?<Type>.{3,}):)?"?(?<Data>[^"]+)"?' {
                If ($Matches.Type)
                {
                    switch ($Matches.Type)
                    {
                        hex     {
                            $Type = 'Binary'
                            If ($Matches.Data -like '*,\')
                            {
                                $Wait = $true
                                $Data = $Matches.Data.TrimEnd('\')
                            }
                            else
                            {
                                $Data = [byte[]]$Matches.Data.Split(',').foreach({"0x$_"})
                            }
                        }
                        'hex(2)' {
                            $Type = 'ExpandString'
                            If ($Matches.Data -like '*,\')
                            {
                                $Wait = $true
                                $Data = $Matches.Data.TrimEnd('\')
                            }
                            else
                            {
                                $Data = [byte[]]$Matches.Data.Split(',').foreach({"0x$_"})
                                $Data = [System.Text.Encoding]::Unicode.GetString($Data) -replace '\\\\','\'
                            }
                        }
                        'hex(7)' {
                            $Type = 'MultiString'
                            If ($Matches.Data -like '*,\')
                            {
                                $Wait = $true
                                $Data = $Matches.Data.TrimEnd('\')
                            }
                            else
                            {
                                $Data = [byte[]]$Matches.Data.Split(',').foreach({"0x$_"})
                                $Data = [System.Text.Encoding]::Unicode.GetString($Data) -replace '\\\\','\'
                            }
                        }
                        dword   {
                            $Type = 'DWORD'
                            $Data = [int]"0x$($Matches.Data)"
                        }
                        Default {
                            $Type = $Matches.Type
                            $Data = $Matches.Data
                        }
                    }
                }
                else
                {
                    $Type = 'String'
                    $Data = $Matches.Data -replace '\\\\','\'
                }
                If ($Matches.Name -eq '@')
                {
                    $Name = '(Default)'
                }
                else
                {
                    $Name = $Matches.Name
                }
                If (!$Wait -and $RegType -eq 'Registry')
                {
                    [Registry]::new($Key,$Name,$Data,$Type,$Description)
                }
            }
            '^;<PF>(.+)</PF>$' {
                $Description = $Matches[1].split('\')[-1]
                [Registry]::new($Key,$Name,$Data,$Type,$Description)
            }
            '^\s+(.{2},?)+\\?'     {
                $Data = $Data + $Matches[0].Trim().TrimEnd('\')
                If ($Matches[0] -notlike '*,\')
                {
                    $Data = [byte[]]$Data.Split(',').foreach({"0x$_"})
                    If ($Type -ne 'Binary')
                    {
                        $Data = [System.Text.Encoding]::Unicode.GetString($Data) -replace '\\\\','\'
                    }
                    [Registry]::new($Key,$Name,$Data,$Type,$Description)
                    $Wait = $false
                }
            }
        }
    }
    catch
    {
        Write-Error -Exception $_.exception
    }
}

#endregion helper functions

#region Functions

<#
.Synopsis
   Connect to a remote RES One Workspace Relayserver
.DESCRIPTION
   Connect to the RES One Workspace cache on a remote Relayserver. If not all users have
   access to the servers registry and admin shares (E.G. C$,D$, etc.) you can share the 
   cache folder manually and use the ShareName parameter to connect to the correct environment.
   Make sure all relayservers have the same share using the same sharename.
.EXAMPLE
   Connect-RESWMRelayServer -Server RelaySvr001
   Connects to Relayserver RelaySvr001
.EXAMPLE
   Connect-RESWMRelayServer -Server RelaySvr001 -Environment RESWM@svr-sql-001
   Connects to environment RESWM@svr-sql-001 on Relayserver RelaySvr001
.EXAMPLE
   Connect-RESWMRelayServer -Server RelaySvr001 -ShareName RESCache$ -Credential CONTOSO\User001
   Connects to the shared cache folder "\\RelaySvr001\RESCache$" as User001
#>
function Connect-RESWMRelayServer
{
    [CmdletBinding(DefaultParameterSetName='Server')]
    [Alias('cwmr')]
    [OutputType()]
    Param
    (
        # Name of RES One Workspace RelayServer
        [Parameter(Mandatory= $true,
                   ValueFromPipelineByPropertyName=$true,
                   ParameterSetName='Share',
                   Position=0)]
        [Parameter(Mandatory= $true,
                   ValueFromPipelineByPropertyName=$true,
                   ParameterSetName='Server',
                   Position=0)]
        [Alias('SamAccountName','Agent')]
        [string]
        $Server,

        # Name of the shared cache folder share (not the full UNC path)
        [Parameter(Mandatory= $true,
                   ParameterSetName='Share')]
        [string]
        $ShareName,

        # Name of the RES WM environment. Required if there are more than one.
        [Parameter(ParameterSetName='Server')]
        [string]
        $Environment,

        # Credential to connect to RelayServer (share).
        [PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        # returns the path of the remote cache location.
        [switch]
        $PassThru
    )

    Process
    {
        $Server = [System.Net.Dns]::GetHostByName($Server).HostName # FQDN
        If (![System.Net.Sockets.TcpClient]::new($Server, 445).Connected)
        {
            Write-Error "Computer [$Server] appears to be offline" -Category ConnectionError -ErrorAction Stop
        }
        If ($PSBoundParameters['ShareName'])
        {
            Write-Verbose 'Using a share to connect to the cache.'
            $Root = "\\$Server\$ShareName"
        }
        else
        {
            Write-Verbose "Connecting to registry on relayserver"
            Try
            {
                $Params = @{
                    Class = "StdRegProv"
                    Namespace = 'root\default'
                    Computername = $Server
                    List = $true
                }
                If ($PSBoundParameters['Credential'])
                {
                    $Params.Add('Credential',$Credential)
                }
                $Registry = Get-Wmiobject @Params
                [uint32]$hklm = 2147483650   
            }
            catch
            {
                Write-Error "Unable to connect to registry" -Category ConnectionError -TargetObject $Server -ErrorAction Stop
            }
            Write-Verbose "Attempting to retreive cache folder on relayerver $Server"
            If (!($Environments = $Registry.EnumKey($hklm,"SOFTWARE\RES\Workspace Manager\RelayServer\Environments\").sNames))
            {
                $Environments = $Registry.EnumKey($hklm,"SOFTWARE\Wow6432Node\RES\Workspace Manager\RelayServer\Environments\").sNames
                $x64 = '\Wow6432Node'
            }
            If ($Environments)
            {
                If (@($Environments).count -eq 1)
                {
                    $Cache = $Registry.GetStringValue($hklm,"SOFTWARE$x64\RES\Workspace Manager\RelayServer\Environments\$Environments\Local",'CacheLocation').sValue
                    $CacheLocation = $Cache.Replace(':','$') + "\$Environments\Cache"
                    $Root = "\\$Server\$CacheLocation"
                }
                elseif ($PSBoundParameters['Environment'])
                {
                    $Environments.ForEach({
                        $EnvironmentName = $Registry.GetStringValue($hklm,"SOFTWARE$x64\RES\Workspace Manager\RelayServer\Environments\$_",'EnvironmentName').sValue
                        If ($EnvironmentName -eq $PSBoundParameters['Environment'])
                        {
                            $Cache = $Registry.GetStringValue($hklm,"SOFTWARE$x64\RES\Workspace Manager\RelayServer\Environments\$_\Local",'CacheLocation').sValue
                            $CacheLocation = $Cache.Replace(':','$') + "\$_\Cache"
                            $Root = "\\$Server\$CacheLocation"
                            continue
                        }
                    })
                }
                else
                {
                    $AllEnvironments = $Environments.ForEach({
                        @{
                            Path = "SOFTWARE$x64\RES\Workspace Manager\RelayServer\Environments\$_"
                            Value = $Registry.GetStringValue($hklm,"SOFTWARE$x64\RES\Workspace Manager\RelayServer\Environments\$_",'EnvironmentName').sValue
                        }
                    })
                    $Environment = Read-Host "Please specify which RES One Workspace environment to connect to ($($AllEnvironments.Value -join ','))"
                    If ($Environment)
                    {
                        If ($ChosenEnv = $AllEnvironments.Where({$_.Value -eq $Environment}))
                        {
                            $Cache = $Registry.GetStringValue($hklm,"$($ChosenEnv.Path)\Local",'CacheLocation').sValue
                            $CacheLocation = $Cache.Replace(':','$') + "\$($ChosenEnv.Path.Split('\')[-1])\Cache"
                            $Root = "\\$Server\$CacheLocation"
                        }
                        else
                        {
                            Write-Error "Environment [$Environment] not recognized. Should be one of the following: $($AllEnvironments.Value -join ',')" -Category ObjectNotFound -ErrorAction Stop
                        }
                    }
                    else
                    {
                        Write-Error "No environment to connect to." -Category NotSpecified -ErrorAction Stop
                    }
                }
            }
            else
            {
                Write-Error "No RelayServer environments found" -Category ObjectNotFound -TargetObject $Server -ErrorAction Stop
            }
        }
        Write-Verbose "Creating PSDrive for path [$Root]"
        $WMCache = @{
            Name = 'WMCache'
            PSProvider = 'FileSystem'
            Root = $Root
        }
        If ($PSBoundParameters['Credential'])
        {
            Write-Verbose 'Using alternate credentials'
            $WMCache.Add('Credential',$Credential)
        }
        Get-PSDrive -Name WMCache  -ErrorAction SilentlyContinue | Remove-PSDrive
        $RESDrive = New-PSDrive @WMCache -Scope global -ErrorAction Stop
        $global:AppMenus = @{}
        $SubFolder = Get-ChildItem WMCache: | sort LastWriteTime | select -Last 1 -ExpandProperty Name
        (Select-Xml WMCache:\$SubFolder\Objects\app_menus.xml -XPath '//objectinfo').Node.foreach({
            $AppMenus.Add($_.guid,$_.config.applicationmenu.title)
        })
        If ((Select-Xml WMCache:\$SubFolder\Objects\respf_agents.xml -XPath '//connection_method').Node.InnerText -eq 'relayserver')
        {
            $global:RelayServers = (Select-Xml WMCache:\$SubFolder\Objects\respf_agents.xml -XPath '//relay_server').Node.InnerText.foreach({
            $_.split(':')[0]})
        }
        If ($PSBoundParameters['PassThru'])
        {
            Return $RESDrive
        }
    }
}


<#
.Synopsis
   Get RES One Workspace application
.DESCRIPTION
   Get RES One Workspace application.
.EXAMPLE
   Get-RESWMApplication -Title 'Internet Explorer'
   Get RESWM Application with title 'Internet Explorer'
.EXAMPLE
   Get-RESWMApplication -Title Microsoft*
   Get RESWM Applications where title starts with Microsoft
.EXAMPLE
   Get-RESWMApplication -AppID 102
   Get RESWM Application with AppID 102
.EXAMPLE
   Get-RESWMApplication -User CONTOSO\User001
   Get RESWM Application(s) for User001
.EXAMPLE
   Get-RESWMApplication -Filter "enabled = 'yes'"
   Get enabled RESWM Applications
.EXAMPLE
   Get-RESWMApplication -Filter "configuration/createmenushortcut = 'yes'"
   Get RESWM Applications that have a shortcut in the start menu
.EXAMPLE
   Get-RESWMStartMenu -Title 'Microsoft Office' | Get-RESWMApplication
   Get RESWM Applications that are located in the start menu folder 'Microsoft Office'
#>
function Get-RESWMApplication
{
    [CmdletBinding(DefaultParameterSetName='Title')]
    [Alias('gwma')]
    [OutputType([RESWMApplication])]
    Param
    (
        # Title of the application
        [Parameter(ParameterSetName='Title',
                   Position=0)]
        [SupportsWildcards()]
        [string]
        $Title,

        # ID of the application
        [Parameter(ParameterSetName='AppID',
                   Position=0)]
        [int]
        $AppID,
        
        # GUID of the application
        [Parameter(ValueFromPipelineByPropertyName=$true,
                   ParameterSetName='ParentGUID',
                   Position=0)]
        [guid]
        $ParentGUID,

        # Start menu folder object
        [Parameter(ValueFromPipeline=$true,
                   ParameterSetName='MenuFolder',
                   Position=0)]
        [RESWMMenu]
        $MenuFolder,

        # User that has access
        [Parameter(ParameterSetName='User',
                   Position=0)]
        [RESWMUser]
        $User,

        # Xpath filter for the application based on the full object
        [string]
        $Filter
    )

    $Params = @{
        Source = 'Objects\apps.xml'
        Type = 'application'
    }
    If ($PSBoundParameters['Title'])
    {
        $Params.Add('Filter',"config/application/configuration/title = '$Title'")
    }
    elseif ($PSBoundParameters['AppID'])
    {
        $Params.Add('Filter',"appid = '$AppID'")
    }
    elseif ($PSBoundParameters['ParentGUID'])
    {
        $Params.Add('Filter',"guid = '{$ParentGUID}'")
    }
    elseif ($PSBoundParameters['Filter'])
    {
        $Params.Add('Filter',$Filter)
    }
    elseif ($PSBoundParameters['MenuFolder'])
    {
        $Params.Add('Filter',"parentguid = '{$($MenuFolder.GUID)}'") 
    }
    elseif ($PSBoundParameters['User'])
    {
        $Params.Add('User',$User)
        return [RESWMApplication[]](Get-RESWMObject @Params) | where {$_.Enabled -eq $true -and $_.Path -ne 'Disabled!'}
    }
    [RESWMApplication[]](Get-RESWMObject @Params)
}

<#
.Synopsis
   Get RES ONE Workspace startmenu folder
.DESCRIPTION
   Get RES ONE Workspace startmenu folder.
.EXAMPLE
   Get-RESWMStartMenu
.EXAMPLE
   Get-RESWMStartMenu -Title *office*
#>
function Get-RESWMStartMenu
{
    [CmdletBinding(DefaultParameterSetName='Name')]
    [Alias('gwmsm')]
    [OutputType([RESWMZone])]
    Param
    (
        # Title of the menu folder
        [Parameter(ParameterSetName='Name',
                   Position=0)]
        [SupportsWildcards()]
        [string]
        $Title,

        # GUID of the menu folder
        [Parameter(ParameterSetName='GUID',
                   Position=0)]
        [guid]
        $GUID
    )

    $Params = @{
        Source = 'Objects\app_menus.xml'
        Type = 'applicationmenu'
    }
    If ($PSBoundParameters['Title'])
    {
        $Params.Add('Filter',"config/applicationmenu/title = '$Title'")
    }
    elseif ($PSBoundParameters['GUID'])
    {
        $Params.Add('Filter',"guid = '{$GUID}'")
    }
    [RESWMMenu[]](Get-RESWMObject @Params)
}

<#
.Synopsis
   Get RES One Workspace Security Role
.DESCRIPTION
   Get RES One Workspace Security Role
.EXAMPLE
   Get-RESWMSecurityRole
   Get all security roles
.EXAMPLE
   Get-RESWMSecurityRole -Name HelpDesk
   Get the security role named HelpDesk
.EXAMPLE
   Get-RESWMSecurityRole -User CONTOSO\User001
   Get the security role(s) for User001
#>
function Get-RESWMSecurityRole
{
    [CmdletBinding(DefaultParameterSetName='Name')]
    [Alias('gwmsr')]
    [OutputType([RESWMSecRole])]
    Param
    (
        # Name of the security role
        [Parameter(ParameterSetName='Name',
                   Position=0)]
        [SupportsWildcards()]
        [string]
        $Name,
        
        # GUID of the security role
        [Parameter(ParameterSetName='GUID',
                   Position=0)]
        [guid]
        $GUID,

        # User that has access
        [Parameter(ParameterSetName='User',
                   Position=0)]
        [RESWMUser]
        $User
    )

    $Params = @{
        Source = 'Objects\sec_role.xml'
        Type = 'securityrole'
    }
    If ($PSBoundParameters['Name'])
    {
        $Params.Add('Filter',"objectdesc = '$Name'")
    }
    elseif ($PSBoundParameters['GUID'])
    {
        $Params.Add('Filter',"guid = '{$GUID}'")
    }
    elseif ($PSBoundParameters['User'])
    {
        $Params.Add('User',$User)
    }
    [RESWMSecRole[]](Get-RESWMObject @Params)
}

<#
.Synopsis
   Get RES One Workspace drive mapping
.DESCRIPTION
   Get RES One Workspace drive mapping
.EXAMPLE
   Get-RESWMMapping
   Get all drive mappings
.EXAMPLE
   Get-RESWMMapping -DriveLetter H
   Get drive mapping for drive H:\
.EXAMPLE
   Get-RESWMMapping -User CONTOSO\User001
   Get drive mapping(s) for User001
#>
function Get-RESWMMapping
{
    [CmdletBinding(DefaultParameterSetName='Letter')]
    [Alias('gwmm')]
    [OutputType([RESWMMapping])]
    Param
    (
        # Device drive letter
        [Parameter(ParameterSetName='Letter',
                   Position=0)]
        $DriveLetter,

        # User that has access
        [Parameter(ParameterSetName='User',
                   Position=0)]
        [RESWMUser]
        $User
    )

    $Params = @{
        Source = 'Objects\pl_map.xml'
        Type = 'mapping'
    }
    If ($PSBoundParameters['DriveLetter'])
    {
        $Params.Add('Filter',"config/mapping/device = '$DriveLetter`:'")
    }
    elseif ($PSBoundParameters['User'])
    {
        $Params.Add('User',$User)
        If (!$RESUserApps)
        {
            $RESUserApps = Get-RESWMApplication -User $User
        }
        return [RESWMMapping[]](Get-RESWMObject @Params) | 
            where ParentGUID -In ($RESUserApps.GUID + [guid]::Empty)
    }
    [RESWMMapping[]](Get-RESWMObject @Params)
}

<#
.Synopsis
   Get RES One Workspace registry
.DESCRIPTION
   Get RES One Workspace registry objects
.EXAMPLE
   Get-RESWMRegistry
   Get all registry objects
.EXAMPLE
   Get-RESWMRegistry -Name iexplore*
   Get registry objects where name starts with iexplore
.EXAMPLE
   Get-RESWMApplication -Title 'Microsoft Word' | Get-RESWMRegistry
   Get registry objects for application 'Microsoft Word'
.EXAMPLE
   Get-RESWMRegistry -User CONTOSO\User001
   Get registry objects for User001
#>
function Get-RESWMRegistry
{
    [CmdletBinding(DefaultParameterSetName='Name')]
    [Alias('gwmr')]
    [OutputType([RESWMRegistry])]
    Param
    (
        # Name of the security role
        [Parameter(ParameterSetName='Name',
                   Position=0)]
        [SupportsWildcards()]
        [string]
        $Name,

        # GUID of the security role
        [Parameter(ParameterSetName='GUID',
                   Position=0)]
        [guid]
        $GUID,

        # User that has access
        [Parameter(ParameterSetName='User',
                   Position=0)]
        [RESWMUser]
        $User,

        # GUID of the parent application
        [Parameter(ValueFromPipelineByPropertyName=$true,
                   ParameterSetName='ParentGUID',
                   Position=0)]
        [guid]
        $ParentGUID
    )

    process
    {
        $Params = @{
            Source = 'Objects\pl_reg.xml'
            Type = 'registry'
        }
        If ($PSBoundParameters['Name'])
        {
            $Params.Add('Filter',"config/registry/name = '$Name'")
        }
        elseif ($PSBoundParameters['GUID'])
        {
            $Params.Add('Filter',"guid = '{$GUID}'")
        }
        elseif ($PSBoundParameters['ParentGUID'])
        {
            $Params.Add('Filter',"parentguid = '{$ParentGUID}'")
        }
        elseif ($PSBoundParameters['User'])
        {
            $Params.Add('User',$User)
            If (!$RESUserApps)
            {
                $RESUserApps = Get-RESWMApplication -User $User
            }
            return [RESWMRegistry[]](Get-RESWMObject @Params) | 
                where ParentGUID -In ($RESUserApps.GUID + [guid]::Empty)
        }
        [RESWMRegistry[]](Get-RESWMObject @Params)
    }
}

<#
.Synopsis
   Get RES ONE Workspace PowerZone
.DESCRIPTION
   Get RES ONE Workspace PowerZone (Locations and Devices)
.EXAMPLE
   Get-RESWMZone
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-RESWMZone
{
    [CmdletBinding(DefaultParameterSetName='Name')]
    [Alias('gwmz')]
    [OutputType([RESWMZone])]
    Param
    (
        # Name of the PowerZone
        [Parameter(ParameterSetName='Name',
                   Position=0)]
        [SupportsWildcards()]
        [string]
        $Name,

        # GUID of the PowerZone
        [Parameter(ParameterSetName='GUID',
                   Position=0)]
        [guid]
        $GUID
    )

    $Params = @{
        Source = 'Objects\pwrzone.xml'
        Type = 'powerzone'
    }
    If ($PSBoundParameters['Name'])
    {
        $Params.Add('Filter',"config/powerzone/name = '$Name'")
    }
    elseif ($PSBoundParameters['GUID'])
    {
        $Params.Add('Filter',"guid = '{$GUID}'")
    }
    [RESWMZone[]](Get-RESWMObject @Params)
}

<#
.Synopsis
   Get RES ONE Workspace User Preference
.DESCRIPTION
   Get RES ONE Workspace User Preference
.EXAMPLE
   Get-RESWMUserPreference -Name 'Office 2016'
   Get a user preference object named 'Office 2016'
.EXAMPLE
   Get-RESWMApplication -Title Notepad | Get-RESWMUserPreference
   Get user preference object(s) for application Notepad
#>
function Get-RESWMUserPreference
{
    [CmdletBinding(DefaultParameterSetName='name')]
    [Alias('gwmup')]
    [OutputType([RESWMUserPref])]
    Param
    (
        # Name of the user preference
        [Parameter(ParameterSetName='name',
                   Position=0)]
        [string]
        $Name,

        # GUID of the user preference
        [Parameter(ParameterSetName='guid',
                   Position=0)]
        [guid]
        $GUID,

        # Application where the user preference is located
        [Parameter(ValueFromPipeline=$true,
                   ParameterSetName='application',
                   Position=0)]
        [RESWMApplication]
        $Application
    )
    Process
    {
        $Params = @{
            Source = 'Objects\user_prefs.xml'
            Type = 'profile'
        }
        If ($PSBoundParameters['Name'])
        {
            $Params.Add('Filter',"config/profile/name = '$Name'")
        }
        elseif ($PSBoundParameters['GUID'])
        {
            $Params.Add('Filter',"guid = '{$GUID}'")
        }
        elseif ($PSBoundParameters['Application'])
        {
            $Params.Add('Filter',"parentguid = '{$($Application.GUID)}'")
        }
        [RESWMUserPref[]](Get-RESWMObject @Params)
    }
}

<#
.Synopsis
   Get RES ONE Workspace printer
.DESCRIPTION
   Get RES ONE Workspace printer
.EXAMPLE
   Get-RESWMPrinter -Printer *\PRT-001
   Get RES WM printer named PRT-001
.EXAMPLE
   Get-RESWMPrinter -Printer \\SRV-PRT-001\*
   Get RES WM printers on printserver SRV-PRT-001
.EXAMPLE
   Get-RESWMPrinter -Driver Lexmark*
   Get RES WM printer with a Lexmark driver
.EXAMPLE
   Get-RESWMPrinter -User CONTOSO\User001
   Get RES WM printer(s) for User001
#>
function Get-RESWMPrinter
{
    [CmdletBinding(DefaultParameterSetName='Name')]
    [Alias('gwmp')]
    [OutputType([RESWMPrinter])]
    Param
    (
        # Path and name of the printer
        [Parameter(ParameterSetName='Name',
                   Position=0)]
        [SupportsWildcards()]
        [string]
        $Printer,

        # GUID of the PowerZone
        [Parameter(ParameterSetName='GUID',
                   Position=0)]
        [guid]
        $GUID,

        [Parameter(ParameterSetName='Driver',
                   Position=0)]
        [SupportsWildcards()]
        [string]
        $Driver,

        # User that has access
        [Parameter(ParameterSetName='User',
                   Position=0)]
        [RESWMUser]
        $User
    )

    $Params = @{
        Source = 'Objects\pl_prn.xml'
        Type = 'printermapping'
    }
    If ($PSBoundParameters['Name'])
    {
        $Params.Add('Filter',"config/printermapping/printer = '$Name'")
    }
    elseif ($PSBoundParameters['GUID'])
    {
        $Params.Add('Filter',"guid = '{$GUID}'")
    }
    elseif ($PSBoundParameters['Driver'])
    {
        $Params.Add('Filter',"config/printermapping/driver = '$Driver'")
    }
    elseif ($PSBoundParameters['User'])
    {
        $Params.Add('User',$User)
        If (!$RESUserApps)
        {
            $RESUserApps = Get-RESWMApplication -User $User
        }
        return ([RESWMPrinter[]](Get-RESWMObject @Params) | 
            where ParentGUID -In ($RESUserApps.GUID + [guid]::Empty))
    }
    [RESWMPrinter[]](Get-RESWMObject @Params)
}

<#
.Synopsis
   Get RES ONE Workspace environment variable
.DESCRIPTION
   Get RES ONE Workspace environment variable
.EXAMPLE
   Get-RESWMVariable -Name DESKPIC
   Get RES WM variable named DESKPIC
.EXAMPLE
   Get-RESWMVariable -User CONTOSO\User001
   Get RES WM variables for User001
#>
function Get-RESWMVariable
{
    [CmdletBinding(DefaultParameterSetName='Name')]
    [Alias('gwmv')]
    [OutputType([RESWMVariable])]
    Param
    (
        # Path and name of the printer
        [Parameter(ParameterSetName='Name',
                   Position=0)]
        [SupportsWildcards()]
        [string]
        $Name,

        # GUID of the PowerZone
        [Parameter(ParameterSetName='GUID',
                   Position=0)]
        [guid]
        $GUID,

        # User that has access
        [Parameter(ParameterSetName='User',
                   Position=0)]
        [RESWMUser]
        $User
    )

    $Params = @{
        Source = 'Objects\pl_var.xml'
        Type = 'Variable'
    }
    If ($PSBoundParameters['Name'])
    {
        $Params.Add('Filter',"config/variable/name = '$Name'")
    }
    elseif ($PSBoundParameters['GUID'])
    {
        $Params.Add('Filter',"guid = '{$GUID}'")
    }
    elseif ($PSBoundParameters['User'])
    {
        $Params.Add('User',$User)
        If (!$RESUserApps)
        {
            $RESUserApps = Get-RESWMApplication -User $User
        }
        return ([RESWMVariable[]](Get-RESWMObject @Params) | 
            where ParentGUID -In ($RESUserApps.GUID + [guid]::Empty))
    }
    [RESWMVariable[]](Get-RESWMObject @Params)
}

<#
.Synopsis
   Get RES ONE Workspace task
.DESCRIPTION
   Get RES ONE Workspace task
.EXAMPLE
   Get-RESWMPrinter -Printer *\PRT-001
   Get RES WM printer named PRT-001
.EXAMPLE
   Get-RESWMPrinter -Printer \\SRV-PRT-001\*
   Get RES WM printers on printserver SRV-PRT-001
.EXAMPLE
   Get-RESWMPrinter -Driver Lexmark*
   Get RES WM printer with a Lexmark driver
.EXAMPLE
   Get-RESWMPrinter -User CONTOSO\User001
   Get RES WM printer(s) for User001
#>
function Get-RESWMTask
{
    [CmdletBinding(DefaultParameterSetName='Description')]
    [Alias('gwmt')]
    [OutputType([RESWMVariable])]
    Param
    (
        # Path and name of the printer
        [Parameter(ParameterSetName='Description',
                   Position=0)]
        [SupportsWildcards()]
        [string]
        $Description,

        # GUID of the PowerZone
        [Parameter(ParameterSetName='GUID',
                   Position=0)]
        [guid]
        $GUID,

        # User that has access
        [Parameter(ParameterSetName='User',
                   Position=0)]
        [RESWMUser]
        $User
    )

    $Params = @{
        Source = 'Objects\pl_task.xml'
        Type = 'exttask'
    }
    If ($PSBoundParameters['Name'])
    {
        $Params.Add('Filter',"config/exttask/description = '$Description'")
    }
    elseif ($PSBoundParameters['GUID'])
    {
        $Params.Add('Filter',"guid = '{$GUID}'")
    }
    elseif ($PSBoundParameters['User'])
    {
        $Params.Add('User',$User)
        If (!$RESUserApps)
        {
            $RESUserApps = Get-RESWMApplication -User $User
        }
        return ([RESWMVariable[]](Get-RESWMObject @Params) | 
            where ParentGUID -In ($RESUserApps.GUID + [guid]::Empty))
    }
    (Get-RESWMObject @Params)
}



<#
.Synopsis
   Update Ivanti Workspace Control agent on (remote) computer
.DESCRIPTION
   Update Ivanti Workspace Control agent on (remote) computer
.EXAMPLE
   Update-RESWMAgentCache -ComputerName PC001
.EXAMPLE
   Get-BrokerMachine -SummaryState Available | Update-RESWMAgentCache | ogv -Title 'Updating Workspace Cache for available desktops'
#>
function Update-RESWMAgentCache
{
    [CmdletBinding()]
    [OutputType([psobject[]])]
    [Alias('uwmac')]
    Param
    (
        # Name of remote computer
        [Parameter(ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [Alias('HostedMachineName','DeviceName','Name','PSComputerName')]
        [string]
        $ComputerName = (Get-PSDrive WMCache).root.Split('\')[2]
    )
    Begin
    {
        $i = 1
        $ActiveJobIDs = Get-Job | select -ExpandProperty Id
    }
    Process
    {
        $null = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $WMService = 'RES'
            If ($env:PROCESSOR_ARCHITECTURE -eq 'AMD64') {
                $path = 'HKLM:\SOFTWARE\WOW6432Node\RES\Workspace Manager'
            }
            else {
                $path = 'HKLM:\SOFTWARE\RES\Workspace Manager'
            }
            $Properties = Get-ItemProperty -Path $path
            if ($Properties.LocalCacheOnDisk -eq 'yes')
            {
                # Remove the Global guid from xml
                [xml]$Xml = Get-Content "$($Properties.LocalCachePath)\UpdateGuids.xml"
                $Xml.updateguids.Global = ''
                $Xml.Save("$($Properties.LocalCachePath)\UpdateGuids.xml")
            }
            else
            {
                $null = Test-Path $path -ErrorAction Stop
                # Remove the Global guid registry value to trigger a cache update
                Remove-Itemproperty -path $path\UpdateGUIDs -name Global
            }
            $Start = Get-Date
            Restart-Service $WMService
            # Wait until the Global key has been recreated
            $result = $null
            $i = 0
            Do 
            {
                if ($Properties.LocalCacheOnDisk -eq 'yes')
                {
                    [xml]$Xml = Get-Content "$($Properties.LocalCachePath)\UpdateGuids.xml"
                    $result = $Xml.updateguids.Global -ne ''
                }
                else
                {
                    $global = Get-Itemproperty -path $path\UpdateGUIDs -name Global -ErrorAction SilentlyContinue
                    $result = $global -ne $null
                }
                Sleep -Milliseconds 500
                $Time = (Get-Date) - $Start
                $i++
            } 
            Until ($result -or ($Time.Minutes -ge 5))
            $Output = [pscustomobject]@{
                Success = $result
                Time = $Time
            }
            return $Output
        } -AsJob
    }
    End
    {
        $Jobs = Get-Job | Where Id -NotIn $ActiveJobIDs
        $Jobs | Receive-Job -Wait -AutoRemoveJob | select PSComputerName,Success,Time
    }
}

<#
.Synopsis
   Get user preference files for a single user
.DESCRIPTION
   Get user preference files for a single user
.EXAMPLE
   Get-RESWMUserPreferenceFiles -UserPreference 'Office 2016' -User CONTOSO\User1234 -ZeroProfilePath O:\pwrmenu
   Get user preference files named 'Office 2016' for user CONTOSO\User1234 on O:\pwrmenu
.EXAMPLE
   Get-RESWMApplication -AppID 104 | Get-RESWMUserPreference | Get-RESWMUserPreferenceFiles -User CONTOSO\User1234
   Get all user preference files on application with Id 104 for user CONTOSO\User1234 and let powershell figure out the Zero Profile path
#>
function Get-RESWMUserPreferenceFiles
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    [Alias('gwmupf')]
    Param
    (
        # RES ONE Workspace application
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   Position=0)]
        [RESWMUserPref]
        $UserPreference,

        # User for whom the cache will be reset
        [Parameter(Mandatory=$true,
                   Position=1)]
        [RESWMUser]
        $User,

        # Path to the users RES profiles
        [Parameter(Mandatory=$false,
                   Position=2)]
        [string]
        $ZeroProfilePath
    )

    Begin
    {
        Test-CacheConnection
        Write-Verbose 'Determining path to users user preferences...'
        If (!$PSBoundParameters['ZeroProfilePath'])
        {
            $SubFolder = Get-ChildItem WMCache: | sort LastWriteTime | select -Last 1 -ExpandProperty Name
            $Drive = (Select-Xml -Path WMCache:\$SubFolder\settings.xml -XPath "//setting[name = 'DriveUserSettings']").Node.value
            $ZeroProfilePath = "$Drive`:" + (Select-Xml -Path WMCache:\$SubFolder\settings.xml -XPath "//setting[name = 'LocationUserSettings']").Node.value
        }
        If ($ZeroProfilePath.StartsWith('\\'))
        {
            $Root = $ZeroProfilePath.replace('%USERNAME%',$User.Name)
        }
        else
        {
            If ($Drive = Get-RESWMMapping -User $User | where Device -EQ "$($ZeroProfilePath.Substring(0,1)):")
            {        
                $ShareName = $Drive.ShareName.replace('%USERNAME%',$User.Name)
                $Root = "$ShareName\$(Split-Path $ZeroProfilePath -Leaf)"
            }
            else
            {
                Write-Error -Message "Unable to find drive mapping [$($ZeroProfilePath.Substring(0,1)):] for this user" -Category ObjectNotFound -ErrorAction Stop
            }
        }
        Write-Verbose "Path to user preference files is [$Root\UserPref]"
        If ($UserPref = Get-Item $Root\UserPref -ErrorAction SilentlyContinue)
        {
            Write-Verbose "Using default credentials to get the files"
        }
        elseif ((Get-PSDrive WMCache).Credential.UserName)
        {
            Write-Verbose "Creating a temporary PSDrive to the share"
            $ZeroProf = New-PSDrive -Name ZeroProf -PSProvider FileSystem -Root $Root -Credential (Get-PSDrive WMCache).Credential -ErrorAction Stop
            $UserPref = Get-Item ZeroProf:\UserPref -ErrorAction Stop
        }
    }
    Process
    {
        If ($PSBoundParameters['UserPreference'])
        {
            $Files = Get-Item "$UserPref\{$($UserPreference.GUID)}.*" -ErrorAction Stop
            return $Files
        }
        elseif ($Files = Get-ChildItem $UserPref -ErrorAction Stop)
        {
            return $Files
        }
        else
        {
            Write-Error "No user preferences found for this user." -Category ObjectNotFound -TargetObject $UserPref
        }
    }
    End
    {
        If ($ZeroProf)
        {
            Write-Verbose 'Removing PSDrive'
            $ZeroProf | Remove-PSDrive
        }
    }
}

<#
.Synopsis
   Reset user preferences for a single user
.DESCRIPTION
   Reset a user preference for a single user by moving the corresponding 
   upf/upr files to a backup folder.
.EXAMPLE
   Reset-RESWMUserPreference -UserPreference 'Office 2016' -User CONTOSO\User1234 -ZeroProfilePath O:\pwrmenu
   Reset user preference named 'Office 2016' for user CONTOSO\User1234 on O:\pwrmenu
.EXAMPLE
   Get-RESWMApplication -AppID 104 | Get-RESWMUserPreference | Reset-RESWMUserPreference -User CONTOSO\User1234
   Reset all user preference object on application with Id 104 and let powershell figure out the Zero Profile path
#>
function Reset-RESWMUserPreference
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    [Alias('rwmup')]
    Param
    (
        # RES ONE Workspace application
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0)]
        [RESWMUserPref]
        $UserPreference,

        # User for whom the cache will be reset
        [Parameter(Mandatory=$true,
                   Position=1)]
        [RESWMUser]
        $User,

        # Path to the users RES profiles
        [Parameter(Mandatory=$false,
                   Position=2)]
        [string]
        $ZeroProfilePath,

        # Show profile files in backup folder
        [switch]
        $PassThru
    )

    Begin
    {
        Test-CacheConnection
        Write-Verbose 'Determining path to users user preferences...'
        If (!$PSBoundParameters['ZeroProfilePath'])
        {
            $SubFolder = Get-ChildItem WMCache: | sort LastWriteTime | select -Last 1 -ExpandProperty Name
            $Drive = (Select-Xml -Path WMCache:\$SubFolder\settings.xml -XPath "//setting[name = 'DriveUserSettings']").Node.value
            $ZeroProfilePath = "$Drive`:" + (Select-Xml -Path WMCache:\$SubFolder\settings.xml -XPath "//setting[name = 'LocationUserSettings']").Node.value
        }
        If ($ZeroProfilePath.StartsWith('\\'))
        {
            $Root = $ZeroProfilePath.replace('%USERNAME%',$User.Name)
        }
        else
        {
            If ($Drive = Get-RESWMMapping -User $User | where Device -EQ "$($ZeroProfilePath.Substring(0,1)):")
            {        
                $ShareName = $Drive.ShareName.replace('%USERNAME%',$User.Name)
                $Root = "$ShareName\$(Split-Path $ZeroProfilePath -Leaf)"
            }
            else
            {
                Write-Error -Message "Unable to find drive mapping [$($ZeroProfilePath.Substring(0,1)):] for this user" -Category ObjectNotFound -ErrorAction Stop
            }
        }

        If ((Get-PSDrive WMCache).Credential.UserName)
        {
            $Credential = (Get-PSDrive WMCache).Credential
        }
        
        $UserPref = Get-Item $Root\UserPref -ErrorAction Stop
        If (!(Test-Path $UserPref\Backup))
        {
            $Backup = New-Item -Path $UserPref -Name Backup -ItemType Directory -ErrorAction Stop
        }
        $MovedFiles = New-Object System.Collections.ArrayList
    }
    Process
    {
        If ($Files = Get-Item "$UserPref\{$($UserPreference.GUID)}.*")
        {
            Foreach ($File in $Files)
            {
                if ($pscmdlet.ShouldProcess($File, "Move to Backup folder"))
                {
                    If ($Credential)
                    {
                        Write-Verbose "Running move command under account [$($Credential.UserName)]"
                        $ScriptBlock = {Param($File,$UserPref) Move-Item -Path "$($File.FullName)" -Destination "$UserPref\Backup\" -Force}
                        Start-Job -ScriptBlock $Scriptblock -ArgumentList $File,$UserPref -Credential $Credential | Receive-Job -Wait -AutoRemoveJob
                    }
                    else
                    {
                        Write-Verbose "Moving file [$($File.Name)] to backup folder."
                        Move-Item -Path $File.FullName -Destination $UserPref\Backup\ -Force
                    }
                    $null = $MovedFiles.Add($File.Name)
                }
            }
        }
        else
        {
            Write-Error "No user preferences found for this user." -Category ObjectNotFound -TargetObject $UserPref
        }
    }
    End
    {
        If ($PSBoundParameters['PassThru'] -and $MovedFiles.Count)
        {
            while ($MovedFiles.ForEach({Test-Path $UserPref\Backup\$_}) -contains $false)
            {
                sleep -Milliseconds 500
            }
            $MovedFiles.ForEach({Get-Item $UserPref\Backup\$_})
        }
    }
}

#endregion Functions
