#region Classes

Using namespace  System.Xml

# Application
class RESWMApplication
{
    [int]        $AppID
    [string]     $Title
    [string]     $Description
    [string]     $Path
    [bool]       $Enabled
    [string]     $CommandLine
    [string]     $Parameters
    [RESWMAccCtrl] $AccessControl
    [string]     $Type
    [XmlElement] $FullObject
    hidden [guid] $GUID
    hidden [guid] $ParentGUID

    RESWMApplication ([string] $Title)
    {
        Get-RESWMApplication -Title $Title
    }

    RESWMApplication ([int] $ObjectID)
    {
        Get-RESWMApplication -AppID $ObjectID
    }

    RESWMApplication ([XmlNode] $XMLNode)
    {
        $this.Enabled = $XMLNode.Enabled -eq 'yes'
        $this.AppID = $XMLNode.AppID
        $this.Title = $XMLNode.configuration.title
        $this.Description = $XMLNode.configuration.description
        $this.CommandLine = $XMLNode.configuration.commandLine
        $this.Parameters = $XMLNode.configuration.parameters
        $this.AccessControl = $XMLNode.AccessControl
        switch -Wildcard ($XMLNode.configuration.commandline)
        {
            *\iexplore.exe {If (!$XMLNode.configuration.parameters -or 
                                $XMLNode.configuration.parameters -notlike '^[-|/]')
                                {$this.Type = 'URL'}}
            *\firefox.exe  {If (!$XMLNode.configuration.parameters -or 
                                $XMLNode.configuration.parameters -notlike '^[-|/]')
                                {$this.Type = 'URL'}}
            *\chrome.exe   {If (!$XMLNode.configuration.parameters -or 
                                $XMLNode.configuration.parameters -notmatch '^[-|/]')
                                {$this.Type = 'URL'}}
            *\mstsc.exe    {If (!$XMLNode.configuration.parameters -or 
                                $XMLNode.configuration.parameters -match '^[-v|/v]')
                                {$this.Type = 'RDP'}}
            *\sfttray.exe  {$this.Type = 'AppV4'}
            %APPVPACK*     {$this.Type = 'AppV5'}
            \\*            {$this.Type = 'NetworkApp'}
            Default        {$this.Type = 'LocalApp'}
        }
        $this.FullObject = $XMLNode
        $this.GUID = $XMLNode.guid
        If ($XMLNode.parentguid.count -gt 1)
        {
            $Parent = $XMLNode.ParentGUID | select -Unique | where {Get-RESWMStartMenu -GUID $_}
            If ($Parent)
            {
                $this.ParentGUID = $Parent
            }
        }
        else
        {
            $this.ParentGUID = $XMLNode.parentguid
        }
        $this.Path = Get-RESWMStartMenu -GUID $this.ParentGUID
        If (!$this.Path)
        {
            $this.Path = 'Disabled!'
        }
    }
}

# Menu folder
class RESWMMenu
{
    [string] $Title
    [string] $Description
    [bool]   $Enabled
    [string] $Path
    hidden [guid] $GUID
    hidden [guid] $ParentGUID
    hidden [guid] $UpdateGUID

    RESWMMenu ([XmlElement] $XMLNode)
    {
        foreach ($Property in [RESWMMenu].GetProperties().Name)
        {
            switch ($this.$Property)
            {
                yes     {$this.$Property = $true}
                no      {$this.$Property = $false}
                default {$this.$Property = $XMLNode.$Property}
            }
        }
        If ($XMLNode.parentguid -eq '{00000000-0000-0000-0000-000000000000}')
        {
            $this.Path = 'Start'
        }
        else
        {
            $MenuNode = (Select-Xml -Path $global:RESWMCache\Objects\menutree.xml -XPath "//menu[@guid = '$($XMLNode.guid)']").Node
            $arrPath = New-Object System.Collections.ArrayList
            Do
            {
                $MenuNode = $MenuNode.ParentNode
                If ($MenuNode.guid)
                {
                    $null = $arrPath.Add($global:AppMenus[($MenuNode.guid)])
                }
            }
            Until (!$MenuNode.guid)
            $null = $arrPath.Add('Start')
            $arrPath.Reverse()
            $this.Path = $arrPath -join '\'
        }
    }

    [string] ToString ()
    {
        return $this.Path + '\' + $this.Title
    }
}

# PowerZone
class RESWMZone
{
    [string] $Name
    [string] $Description
    [object] $Rules
    [bool]   $Enabled
    [string] $ObjectDesc
    hidden [guid] $Guid
    hidden [guid] $UpdateGuid

    RESWMZone ([XmlElement] $XMLNode)
    {
        foreach ($Property in [RESWMZone].GetProperties().Name)
        {
            switch ($this.$Property)
            {
                yes     {$this.$Property = $true}
                no      {$this.$Property = $false}
                default {$this.$Property = $XMLNode.$Property}
            }
        }
    }
}

# AD Organizational Unit
class RESWMOU
{
    [string] $Name
    [string] $DistinghuishedName
    [string] $Description

    RESWMOU ([XmlNode] $XMLNode)
    {
        $objGUID = ($XMLNode.InnerText -split '(.{2})').where({$_}) -join '\'
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $Domain = $forest.Domains | where Name -Like "$($XMLNode.domain).*"
        $OU = [adsisearcher]::new($Domain.GetDirectoryEntry(),"objectGUID=\$objGUID").FindAll()
        $this.Name = $OU[0].Properties.name
        $this.DistinghuishedName = $OU.Properties.distinguishedname[0]
        $this.Description = $OU.Properties.description
    }

    [string] ToString()
    {
        return $this.Name
    }
}

# AD user
class RESWMUser
{
    [string] $Name
    [string] $DistinghuishedName
    [string] $Domain
    [string[]] $MemberOf

    RESWMUser ([string] $User)
    {
        $UserName = $User.Split('\')[1]
        $DomainName = $User.Split('\')[0]
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $ADDomain = $forest.Domains | where Name -Like "$DomainName.*"
        $ADSearcher = [adsisearcher]::new($ADDomain.GetDirectoryEntry(),"(&(objectClass=user)(SamAccountName=$UserName))")
        $ADSearcher.PropertiesToLoad.AddRange(@('name','distinguishedname','objectClass','memberof'))
        $Account = $ADSearcher.FindAll()
        $this.Name = $Account.Properties.name[0]
        $this.DistinghuishedName = $Account.Properties.distinguishedname[0]
        $this.Domain = $DomainName
        $this.MemberOf = $Account.Properties.memberof.TrimStart('CN=').foreach({
            $GroupName = $_.Split(',')[0]
            $DomainName = $_.Split(',').where({$_ -like 'DC=*'})[0].TrimStart('DC=')
            "$DomainName\$GroupName"
        })
    }

    RESWMUser ([string] $UserName, [string] $Domain)
    {
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $ADDomain = $forest.Domains | where Name -Like "$Domain.*"
        $ADSearcher = [adsisearcher]::new($ADDomain.GetDirectoryEntry(),"(&(objectClass=user)(SamAccountName=$UserName))")
        $ADSearcher.PropertiesToLoad.AddRange(@('name','distinguishedname','objectClass','memberof'))
        $User = $ADSearcher.FindAll()
        $this.Name = $User.Properties.name[0]
        $this.DistinghuishedName = $User.Properties.distinguishedname[0]
        $this.Domain = $Domain
        $this.MemberOf = $User.Properties.memberof.TrimStart('CN=').foreach({
            $GroupName = $_.Split(',')[0]
            $DomainName = $_.Split(',').where({$_ -like 'DC=*'})[0].TrimStart('DC=')
            "$DomainName\$GroupName"
        })
    }

    [string] ToString()
    {
        return $this.Domain + '\' + $this.Name
    }
}

class RESWMAccCtrl
{
    [string] $AccessMode
    [string] $ZoneMode
    [RESWMAccess[]] $Access

    RESWMAccCtrl ([XmlElement] $XMLNode)
    {
        $this.AccessMode = $XMLNode.access_mode
        $this.ZoneMode = $XMLNode.zone_mode
        switch ($XMLNode.accesstype)
        {
            all       {$this.Access = 'Everyone'}
            group     {$this.Access = $XMLNode.grouplist.group}
            secrole   {$this.Access = $XMLNode.secroles.secrole.foreach({
                            Get-RESWMSecurityRole -GUID $_})}
            delegated {$this.Access = @($XMLNode.appmanlist.appmanglobal).foreach({
                            [RESWMAccess]::new($_,'Delegated')})}
            ou        {$this.Access = $XMLNode.oufingerprint.ou}
            default   {$this.Access = $XMLNode.access}
        }
    }

    [string] ToString()
    {
        return $this.Access.ForEach({$_.ToString()}) -join " $($this.AccessMode.ToLower()) "
    }
}

class RESWMAccess
{
    [string] $Type
    [string] $Object
    [string] $SID
    [string] $Options

    RESWMAccess ([XmlElement] $XMLNode)
    {
        $this.Type = $XMLNode.type
        switch ($this.Type)
        {
            global         {$this.Object = 'EveryOne'}
            group          {$this.Object = If ($XMLNode.object){$XMLNode.object}else{$XMLNode.InnerText}}
            user           {$this.Object = If ($XMLNode.object){$XMLNode.object}else{$XMLNode.InnerText}}
            powerzone      {$this.Object = Get-RESWMZone -GUID $XMLNode.object}
            notinpowerzone {$this.Object = Get-RESWMZone -GUID $XMLNode.object}
            S              {$this.Object = [RESWMOU[]]$XMLNode;$this.Type = 'OU'}
            orchestra      {$this.Object = $XMLNode.services} # NOT IN ENVIRONMENT!!!!
            default        {$this.Object = $XMLNode.InnerText}
        }
        $this.SID = $XMLNode.sid
        $this.Options = $XMLNode.options
    }

    RESWMAccess ([XmlElement] $XMLNode, [string] $Type)
    {
        $this.Type = $Type
        switch ($Type)
        {
            Delegated {$this.SID = $XMLNode.sid;$this.object = $XMLNode.InnerText}
        }
    }

    RESWMAccess ([string] $String)
    {
        switch ($String)
        {
            Everyone {$this.Object = $String;$this.Type = 'global'}
        }
    }

    [string] ToString()
    {
        $String = ''
        switch ($this.Type)
        {
            global         {$String = $this.Object}
            powerzone      {$String = "Zone: [$($this.Object)]"}
            notinpowerzone {$String = "NotZone: [$($this.Object)]"}
            group          {If ($this.Options -eq 'notingroup'){
                                $String = "NotGroup: [$($this.Object)]"
                           } else {
                               $String = "Group: [$($this.Object)]"
                           }}
            user           {If ($this.Options -eq 'notuser'){
                               $String = "NotUser: [$($this.Object)]"
                           } else {
                               $String = "User: [$($this.Object)]"
                           }}
            OU             {$String = "OU: [$($this.Object)]"}
            orchestra      {$String = "RESID: [$this.Object]"}
            delegated      {$String = "Delegated: [$($this.Object)]"}
            default        {$String = "[$($this.Object)]"}
        }
        return $String
    }
}

class RESWMSecRole
{
    [string]      $Name
    [string]      $Description
    [XmlNode]     $Nodes
    [RESWMZone[]] $PowerZones
    [XmlNode]     $Scope
    [RESWMAccCtrl] $AccessControl
    hidden [GUID] $Guid
    hidden [GUID] $UpdateGuid
    [bool] $Enabled

    RESWMSecRole ([XmlElement] $XMLNode)
    {
        foreach ($Property in [RESWMSecRole].GetProperties().Name)
        {
            switch ($Property)
            {
                Name {$this.Name = $XMLNode.objectdesc}
                Enabled {$this.Enabled = $XMLNode.enabled -eq 'yes'}
                default {If ($XMLNode.$Property){$this.$Property = $XMLNode.$Property}}
            }
        }
    }
}

class RESWMMapping
{
    [string] $Device
    [string] $Description
    [string] $ShareName
    [string] $FriendlyName
    [RESWMAccCtrl] $Accesscontrol
    [bool]   $Enabled
    [string] $Action
    [bool]   $FastConnect
    [string] $HideDrive
    [string] $Username
    [string] $Password
    [string] $PasswordLong
    [bool]   $Prompt
    [string] $State
    hidden [int]  $Order
    hidden [guid] $Guid
    hidden [guid] $UpdateGuid
    hidden [guid] $ParentGuid

    RESWMMapping ([XmlElement] $XMLNode)
    {
        foreach ($Property in [RESWMMapping].GetProperties().Name)
        {
            switch ($this.$Property)
            {
                yes     {$this.$Property = $true}
                no      {$this.$Property = $false}
                default {$this.$Property = $XMLNode.$Property}
            }
        }
    }

    [string] ToString()
    {
        return $this.ShareName
    }
}

class RESWMUserPref
{
    [string] $ConfigView
    [string] $Name
    [string] $Description
    [RESWMAccCtrl] $AccessControl
    [psobject] $Settings
    [psobject] $Exclusions
    [guid]   $GUID
    [string] $Location
    hidden [guid]   $UpdateGuid
    hidden [guid]   $ParentGuid
    [bool]   $Enabled
    hidden [string] $ObjectDesc

    RESWMUserPref ([XmlElement] $XMLNode)
    {
        foreach ($Property in [RESWMUserPref].GetProperties().Name)
        {
            switch ($XMLNode.$Property)
            {
                yes     {$this.$Property = $true}
                no      {$this.$Property = $false}
                default {$this.$Property = $XMLNode.$Property}
            }
        }
        switch ($this.ParentGuid.ToString())
        {
            00000000-0000-0000-0000-000000000000 {$this.Location = 'Global'}
            default {$this.Location = 'Application'}
        }
        If ($XMLNode.Mode -eq 'preserve_all')
        {
            $this.Settings = 'PreserveAll'
        }
    }

    [string] ToString()
    {
        return $this.Name
    }

    [RESWMApplication] GetParentApplication ()
    {
        return (Get-RESWMApplication -ParentGUID $this.ParentGuid)
    }
}

class RESWMRegistry
{
    [string]       $Name
    [string]       $Description
    [RESWMAccCtrl] $AccessControl
    [bool]         $Enabled
    [string]       $Type
    [Registry[]]   $Registry
    [string]       $Location
    [string]       $State
    [string]       $ObjectDesc
    [int]          $Order
    [bool]         $Runonce
    [string]       $RunonceFile
    hidden [guid]  $ParentGuid
    hidden [guid]  $GUID
    hidden [guid]  $UpdateGuid

    RESWMRegistry ([XmlElement] $XMLNode)
    {
        foreach ($Property in [RESWMRegistry].GetProperties().Name)
        {
            switch ($XMLNode.$Property)
            {
                yes     {$this.$Property = $true}
                no      {$this.$Property = $false}
                default {$this.$Property = $XMLNode.$Property}
            }
        }
        switch ($this.ParentGuid.ToString())
        {
            00000000-0000-0000-0000-000000000000 {$this.Location = 'Global'}
            default {$this.Location = 'Application'}
        }
        $this.Registry = Get-WMREGFile "$global:RESWMCache\Resources\pl_reg\{$($this.GUID)}.reg"
    }
}

class Registry
{
    [string]   $Key
    [string]   $Value
    [psobject] $Data
    [string]   $Type
    [string]   $Description

    Registry ([string]$Key,[string]$Value,[psobject]$Data,[string]$Type,[string]$Description)
    {
        $this.Key   = $Key
        $this.Value = $Value
        $this.Data  = $Data
        $this.Type  = $Type
        $this.Description = $Description
    }

    [string] ToString ()
    {
        return $this.Value
    }
}

# Printer
class RESWMPrinter
{
    [string] $Printer
    [string] $BackupPrinter
    [bool]   $Default
    [RESWMAccCtrl] $AccessControl
    [string] $Comment
    [string] $Description
    [string] $Driver
    [bool]   $Enabled
    [bool]   $Failover
    [bool]   $FastConnect
    [string] $Location    
    [int]    $Order    
    [string] $PrinterPreference
    [string] $State
    [bool]   $WaitForTask
    hidden [guid] $GUID
    hidden [guid] $ParentGUID
    hidden [guid] $UpdateGUID
    #$objectdesc

    RESWMPrinter ([XmlElement] $XMLNode)
    {
        foreach ($Property in [RESWMPrinter].GetProperties().Name)
        {
            switch ($XMLNode.$Property)
            {
                yes     {$this.$Property = $true}
                no      {$this.$Property = $false}
                default {$this.$Property = $XMLNode.$Property}
            }
        }
    }

    [string] ToString ()
    {
        return $this.Printer
    }
}

#endregion Classes
