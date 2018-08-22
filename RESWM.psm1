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
            foreach ($Time in (1..4))
            {
                If (Test-Connection $Server -Count 1 -Quiet)
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
                        Connect-RESWMRelayServer @Params
                    }
                    return
                }
                else
                {
                    sleep -Milliseconds 3
                }
            }
            $Params = @{
                Message = "Connection to cache on $Server is lost."
                Category = 'ConnectionError'
                TargetObject = $Server
                RecommendedAction = "Connect to a differrent computer."
                ErrorAction = 'Stop'
            }
            Write-Error @Params
        }
    }
    else
    {
        Write-Error "Not connected to RES WM cache" -Category ConnectionError -RecommendedAction "Run command Connect-RESWMCache"
    }
}

<#
.Synopsis
   Get a RES WM object from a cache xml
.DESCRIPTION
   Get a RES WM object from a cache xml
.EXAMPLE
   Get-RESWMObject -Source Objects\apps.xml -Node application -Filter "enabled = 'yes'"
.EXAMPLE
   Get-RESWMObject -Source Objects\apps.xml -Node application -User CONTOSO\User001
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

        # Name of the node we need
        [Parameter(Mandatory=$true)]
        [string]
        $Node,

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
    [xml]$XML = (Get-Content WMCache:\$Source).Trim() # Trim counters empty (Description) node issue
    $FullFilter = ''
    If ($PSBoundParameters['Filter'])
    {
        $Filters = $Filter -split '\b(and|or)'
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
        $FullFilter = "[$($FullFilterArray -join ' ')]"
    }
    elseif ($PSBoundParameters['User'])
    {
        switch ($Node)
        {
            application  {
                $GroupCheck = $User.MemberOf.ForEach({"*/*/*/grouplist/group='$_'"}) -join ' or '
                $NotGroupCheck = '(not(' + ($User.MemberOf.ForEach({"*/*/*/notgrouplist/group='$_'"}) -join ' or ') + '))'
                $UserCheck = "*/*/*/grouplist/group='$User'"
                $NotUserCheck = "(not(*/*/*/notgrouplist/group='$User'))"
                $Everyone = "*/*/*/accesstype='all'"
                $FullFilter = "[(*/*/*/*/ou = '$($User.ParentOU)' or $Everyone or $UserCheck or $GroupCheck) and ($NotGroupCheck or $NotUserCheck) and (not(system = 'yes'))]"
            }
            Default      {
                $GroupCheck = $User.MemberOf.ForEach({"(*/*/*/access[object='$_' and (not(options='notingroup'))])"}) -join ' or '
                $UserCheck = "(*/*/*/access[object='$User' and (not(options='notuser'))])"
                $Everyone = "*/*/*/access/type='global'"
                $FullFilter = "[(*/*/*/*/ou = '$($User.ParentOU)' or $Everyone or $UserCheck or $GroupCheck) and (not(system = 'yes'))]"
            }
        }
    }
    elseif ($Node -ne 'securityrole')
    {
        $FullFilter = "[(not(system = 'yes'))]"
    }
    If ($Node -eq 'application')
    {
        Select-Xml -Xml $XML -XPath "/*/*$FullFilter" | select -ExpandProperty Node
    }
    else
    {
        Select-Xml -Xml $XML -XPath "/*/*$FullFilter" | select -ExpandProperty Node | Set-CapitalizedXMLValues -PassThru
    }
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
    Param ($File)

    $RegType = 'Policy'
    switch -Regex -File $File
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

#endregion helper functions

#region Functions

<#
.Synopsis
   Connect to a remote RES One Workspace Relayserver
.DESCRIPTION
   Connect to the RES One Workspace cache on a remote Relayserver.
.EXAMPLE
   Connect-RESWMRelayServer -Server RelaySvr001
   Connecting to Relayserver RelaySvr001
.EXAMPLE
   Connect-RESWMRelayServer -Server RelaySvr001 -Environment RESWM@svr-sql-001
   Connecting to environment RESWM@svr-sql-001 on Relayserver RelaySvr001
#>
function Connect-RESWMRelayServer
{
    [CmdletBinding()]
    [Alias('cwmr')]
    [OutputType()]
    Param
    (
        # Name of RES One Workspace RelayServer
        [Parameter(ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [Alias('SamAccountName','Agent')]
        [string]
        $Server,

        # Credential to connect to RelayServer.
        [PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        # Name of the RES WM environment. Required if there are more than one.
        [string]
        $Environment,

        # returns the path of the remote cache location.
        [switch]
        $PassThru
    )

    Process
    {
        $Server = [System.Net.Dns]::GetHostByName($Server).HostName # FQDN
        If (!(Test-Connection -ComputerName $Server -Count 1 -Quiet))
        {
            Write-Error "Computer [$Server] appears to be offline" -Category ConnectionError -ErrorAction Stop
        }
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
        Write-Verbose "Attempting to retreive cache folder on Relay Server $Server"
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
                $StageID = $Registry.GetStringValue($hklm,"SOFTWARE$x64\RES\Workspace Manager\RelayServer\Environments\$Environments\Local",'StageId').sValue
                $CacheLocation = $Cache.Replace(':','$') + "\$Environments\Cache\$StageID"
            }
            elseif ($PSBoundParameters['Environment'])
            {
                $Environments.ForEach({
                    $EnvironmentName = $Registry.GetStringValue($hklm,"SOFTWARE$x64\RES\Workspace Manager\RelayServer\Environments\$_",'EnvironmentName').sValue
                    If ($EnvironmentName -eq $PSBoundParameters['Environment'])
                    {
                        $Cache = $Registry.GetStringValue($hklm,"SOFTWARE$x64\RES\Workspace Manager\RelayServer\Environments\$_\Local",'CacheLocation').sValue
                        $StageID = $Registry.GetStringValue($hklm,"SOFTWARE$x64\RES\Workspace Manager\RelayServer\Environments\$_\Local",'StageId').sValue
                        $CacheLocation = $Cache.Replace(':','$') + "\$_\Cache\$StageID"
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
                        $StageID = $Registry.GetStringValue($hklm,"$($ChosenEnv.Path)\Local",'StageId').sValue
                        $CacheLocation = $Cache.Replace(':','$') + "\$($ChosenEnv.Path.Split('\')[-1])\Cache\$StageID"
                    }
                    else
                    {
                        Write-Error "Environment [$Environment] not recognized. Should be one of the following: $($AllEnvironments.Value -join ',')" -Category ObjectNotFound -ErrorAction Stop
                    }
                }
                else
                {
                    Write-Error "No enviroment to connect to." -Category NotSpecified -ErrorAction Stop
                }
            }
            $WMCache = @{
                Name = 'WMCache'
                PSProvider = 'FileSystem'
                Root = "\\$Server\$CacheLocation"
            }
            If ($PSBoundParameters['Credential'])
            {
                $WMCache.Add('Credential',$Credential)
            }
            Get-PSDrive -Name WMCache  -ErrorAction SilentlyContinue | Remove-PSDrive
            $RESDrive = New-PSDrive @WMCache -Scope global -ErrorAction Stop
            $global:AppMenus = @{}
            (Select-Xml WMCache:\Objects\app_menus.xml -XPath '//objectinfo').Node.foreach({
                $AppMenus.Add($_.guid,$_.config.applicationmenu.title)
            })
        }
        else
        {
            Write-Error "No RelayServer environments found" -Category ObjectNotFound -TargetObject $Server -ErrorAction Stop
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
        Node = 'application'
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
        Node = 'applicationmenu'
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
        Node = 'securityrole'
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
        Node = 'mapping'
    }
    If ($PSBoundParameters['DriveLetter'])
    {
        $Params.Add('Filter',"config/mapping/device = '$DriveLetter`:'")
    }
    elseif ($PSBoundParameters['User'])
    {
        $Params.Add('User',$User)
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
    [OutputType()]
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
            Node = 'registry'
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
        Node = 'powerzone'
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
            Node = 'profile'
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
        Node = 'printermapping'
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
    [RESWMPrinter[]](Get-RESWMObject @Params)
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
            switch ($env:PROCESSOR_ARCHITECTURE) {
                x86   {$RegPath = "HKLM:\SOFTWARE\RES\Workspace Manager"}
                AMD64 {$RegPath = "HKLM:\SOFTWARE\WOW6432Node\RES\Workspace Manager"}
            }
            $null = Test-Path $RegPath -ErrorAction Stop
            $Start = Get-Date
            $GlobalGUID = Get-ItemProperty -Path $RegPath\UpdateGUIDs -Name Global
            If ($GlobalGUID.Global)
            {
                Set-ItemProperty -Path $RegPath\UpdateGUIDs -Name Global -Value $null
            }
            Restart-Service $WMService
            Do
            {
                $GlobalGUID = Get-ItemProperty -Path $RegPath\UpdateGUIDs -Name Global
                If ($GlobalGUID.Global)
                {
                    $Time = (Get-Date) - $Start
                    $Output = [pscustomobject]@{
                        Success = $true
                        Time = $Time
                    }
                    return $Output
                }
                else
                {
                    $Time = (Get-Date) - $Start
                    sleep -Seconds 1
                }
            }
            Until ($Time.Minutes -eq 5)
            $Output = [pscustomobject]@{
                Success = $false
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
   Reset user preferences for a single user
.DESCRIPTION
   Reset a user preference for a single user by moving the corresponding 
   upf/upr files to a backup folder.
.EXAMPLE
   Reset-RESWMUserPreference -UserPreference 'Office 2016' -User CONTOSO\User1234 -ZeroProfilePath O:\pwrmenu
   Reset user preference named 'Office 2016' for user CONTOSO\User1234 on O:\pwrmenu
.EXAMPLE
   Get-RESWMApplication -AppID 104 | Get-RESWMUserPreference | Reset-RESWMUserPreference -User CONTOSO\User1234 -ZeroProfilePath \\SVR-FILE-001\%USERNAME%$\pwrmenu
   Reset all user preference object on application with Id 104
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
        Write-Verbose 'Determining path to users user preferences...'
        If (!$PSBoundParameters['ZeroProfilePath'])
        {
            $Drive = (Select-Xml -Path WMCache:\settings.xml -XPath "//setting[name = 'DriveUserSettings']").Node.value
            $ZeroProfilePath = "$Drive`:" + (Select-Xml -Path WMCache:\settings.xml -XPath "//setting[name = 'LocationUserSettings']").Node.value
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
