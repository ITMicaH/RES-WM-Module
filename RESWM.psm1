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
        $Computer = $Drive.Root.Split('\')[2]
        If ($Computer -ne 'localhost')
        {
            foreach ($Time in (1..4))
            {
                If (Test-Connection $Computer -Count 1 -Quiet)
                {
                    return
                }
                else
                {
                    sleep -Milliseconds 3
                }
            }
            $Params = @{
                Message = "Connection to cache on $Computer is lost."
                Category = 'ConnectionError'
                TargetObject = $Computer
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
#>
function Get-RESWMObject
{
    [CmdletBinding()]
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
        [string]
        $Filter,

        # Filter on user
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
                $GroupCheck = $User.MemberOf.ForEach({"*/grouplist/group='$_'"}) -join ' or '
                $NotGroupCheck = '(not(' + ($User.MemberOf.ForEach({"*/notgrouplist/group='$_'"}) -join ' or ') + '))'
                $UserCheck = "*/grouplist/group='$User'"
                $NotUserCheck = "(not(*/notgrouplist/group='$User'))"
                $Everyone = "*/accesstype='all'"
                $FullFilter = "[(*/*/ou = '$($User.ParentOU)' or $Everyone or $UserCheck or $GroupCheck) and ($NotGroupCheck or $NotUserCheck) and (not(system = 'yes'))]"
            }
            Default      {
                $GroupCheck = $User.MemberOf.ForEach({"(*/access[object='$_' and (not(options='notingroup'))])"}) -join ' or '
                $UserCheck = "(*/access[object='$User' and (not(options='notuser'))])"
                $Everyone = "*/access/type='global'"
                $FullFilter = "[(*/*/ou = '$($User.ParentOU)' or $Everyone or $UserCheck or $GroupCheck) and (not(system = 'yes'))]"
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
   Connect to a remote RES One Workspace cache
.DESCRIPTION
   Connect to the RES One Workspace cache on a remote Relay server or an agent.
.EXAMPLE
   Connect-RESWMCache -ComputerName RelaySvr001
   Connecting to cache on Relay server RelaySvr001
.EXAMPLE
   Connect-RESWMCache -ComputerName WMAgent001 -Type Agent
   Connecting to cache on agent WMAgent001
#>
function Connect-RESWMCache
{
    [CmdletBinding()]
    [Alias('cwmc')]
    [OutputType()]
    Param
    (
        # Name of RES One Workspace Agent
        [Parameter(ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [Alias('SamAccountName','Agent')]
        [string]
        $ComputerName = 'localhost',

        # Type of cache you're connecting to.
        [ValidateSet('RelayServer','Agent')]
        [string]
        $Type = 'Agent',

        # Credential to connect to remote agent.
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
        $ComputerName = [System.Net.Dns]::GetHostByName($ComputerName).HostName # FQDN
        If (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)
        {
            If ($Type -eq 'RelayServer')
            {
                $Subkey = 'RelayServer'
            }
            Try
            {
                Switch -Wildcard ($ComputerName)
                {
                    "$env:COMPUTERNAME.*" {$Registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Default')}
                    Default               {$Registry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)}
                }
                
                Write-Verbose 'Registrykey is available'
                If (!($RESWMKey = $Registry.OpenSubKey("SOFTWARE\WOW6432Node\RES\Workspace Manager\$Subkey")))
                {
                    If (!($RESWMKey = $Registry.OpenSubKey("SOFTWARE\RES\Workspace Manager\$Subkey")))
                    {
                        Write-Error "RES ONE Workspace is not installed on computer [$ComputerName]" -Category NotInstalled -ErrorAction Stop
                    }
                }
            }
            catch
            {
                Write-Error "Unable to connect to registry" -Category ConnectionError -TargetObject $ComputerName -ErrorAction Stop
            }
            switch ($Type)
            {
                <#RelayServer {
                    Write-Verbose "Attempting to retreive cache folder on Relay Server $ComputerName"
                    If ($Environments = $RESWMKey.OpenSubKey('Environments'))
                    {
                        If ($Environments.GetSubKeyNames().count -eq 1)
                        {
                            $EnvironmentID = $Environments.GetSubKeyNames()
                            $CacheLocation = $Environments.OpenSubKey("$EnvironmentID\Local").GetValue('CacheLocation').Replace(':','$')
                            $global:RESWMCache = Get-ChildItem "\\$ComputerName\$CacheLocation\$EnvironmentID\Cache" | select -Last 1 | Get-Item
                        }
                        elseif ($PSBoundParameters['Environment'])
                        {
                            $Environments.GetSubKeyNames().ForEach({
                                If ($Environments.OpenSubKey($_).GetValue('EnvironmentName') -eq $PSBoundParameters['Environment'])
                                {
                                    $CacheLocation = $Environments.OpenSubKey("$_\Local").GetValue('CacheLocation').Replace(':','$')
                                    $global:RESWMCache = Get-ChildItem "\\$ComputerName\$CacheLocation\$EnvironmentID\Cache" | select -Last 1 | Get-Item
                                    continue
                                }
                            })
                        }
                        else
                        {
                            $AllEnvironments = $Environments.GetSubKeyNames().ForEach({
                                $Environments.OpenSubKey($_).GetValue('EnvironmentName')
                            })
                            Write-Error "Please specify which RES One Workspace environment to connect to: $($AllEnvironments -join ',')" -Category NotSpecified -ErrorAction Stop
                        }
                    }
                    else
                    {
                        Write-Error "No RelayServer environments found" -Category ObjectNotFound -TargetObject $ComputerName -ErrorAction Stop
                    }
                }#>
                Agent {
                    Write-Verbose "Attempting to retreive cache folder on Agent $ComputerName"
                    $WMCache = @{
                        Name = 'WMCache'
                        PSProvider = 'FileSystem'
                        Root = "\\$ComputerName\$($RESWMKey.GetValue('InstallDir').Replace(':','$'))Data\DBCache"
                    }
                    If ($Registry.GetValue('LocalCachePath'))
                    {
                        $WMCache.Root = "\\$ComputerName\$($RESWMKey.GetValue('LocalCachePath').Replace(':','$'))"
                    }
                    If ($PSBoundParameters['Credential'])
                    {
                        $WMCache.Add('Credential',$Credential)
                    }
                    Get-PSDrive -Name WMCache  -ErrorAction SilentlyContinue | Remove-PSDrive
                    $RESDrive = New-PSDrive @WMCache -Scope global -ErrorAction Stop
                    #[RESWMConnection]$global:RESWMCache = $WMCache
                    $global:AppMenus = @{}
                    (Select-Xml WMCache:\Objects\app_menus.xml -XPath '//applicationmenu').Node.foreach({
                        $AppMenus.Add($_.guid,$_.title)
                    })
                }
            }
        }
        else
        {
            Write-Error "Computer [$ComputerName] appears to be offline" -Category ConnectionError
            return
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
        $Params.Add('Filter',"configuration/title = '$Title'")
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
        return [RESWMApplication[]](Get-RESWMObject @Params) | where Path -NE 'Disabled!'
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
        $Params.Add('Filter',"title = '$Title'")
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
        Source = 'Objects\mappings.xml'
        Node = 'mapping'
    }
    If ($PSBoundParameters['DriveLetter'])
    {
        $Params.Add('Filter',"device = '$DriveLetter`:'")
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
            $Params.Add('Filter',"name = '$Name'")
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
        $Params.Add('Filter',"Name = '$Name'")
    }
    elseif ($PSBoundParameters['GUID'])
    {
        $Params.Add('Filter',"guid = '{$GUID}'")
    }
    [RESWMZone[]](Get-RESWMObject @Params)
}

<#
.Synopsis
   Get RES ONE Workspace PowerZone
.DESCRIPTION
   Get RES ONE Workspace PowerZone
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

    $Params = @{
        Source = 'Objects\user_prefs.xml'
        Node = 'desktop_userpreferences/profile'
    }
    If ($PSBoundParameters['Name'])
    {
        $Params.Add('Filter',"Name = '$Name'")
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
        $Params.Add('Filter',"printer = '$Name'")
    }
    elseif ($PSBoundParameters['GUID'])
    {
        $Params.Add('Filter',"guid = '{$GUID}'")
    }
    elseif ($PSBoundParameters['Driver'])
    {
        $Params.Add('Filter',"driver = '$Driver'")
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
        $ZeroProfilePath = 'U:\pwrmenu',

        # Show profile files in backup folder
        [switch]
        $PassThru
    )

    Begin
    {
        Write-Verbose 'Determining path to users user preferences...'
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
                        Start-Process powershell.exe -ArgumentList "-Command `"Move-Item -Path '$($File.FullName)' -Destination '$UserPref\Backup\' -Force`"" -WindowStyle Hidden -Credential $Credential
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
            Write-Error "No user preferences found for this user." -Category ObjectNotFound
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
