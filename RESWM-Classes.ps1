#region Classes

Using namespace  System.Xml

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
    [string]   $Name
    [string]   $DistinguishedName
    [string]   $Domain
    [string[]] $MemberOf
    [string]   $SID
    hidden [string]   $ParentOU

    RESWMUser ([string] $User)
    {
        If ($User -notlike '*\*')
        {
            $UserName = $User
            $DomainName = $env:USERDOMAIN
        }
        else
        {
            $UserName = $User.Split('\')[1]
            $DomainName = $User.Split('\')[0]
        }
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $ADDomain = $forest.Domains | where Name -Like "$DomainName.*"
        $ADSearcher = [adsisearcher]::new($ADDomain.GetDirectoryEntry(),"(&(objectClass=user)(SamAccountName=$UserName))")
        $ADSearcher.PropertiesToLoad.AddRange(@('name','distinguishedname','objectClass','objectsid','memberof'))
        $Account = $ADSearcher.FindAll()
        $this.Name = $Account.Properties.name[0]
        $this.DistinguishedName = $Account.Properties.distinguishedname[0]
        $this.Domain = $DomainName
        $MemberShip = New-Object System.Collections.ArrayList
        $Groups = [adsisearcher]"(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:=$($this.DistinguishedName)))"
        $Groups.FindAll().ForEach({
            $GroupName = $_.Properties.samaccountname[0]
            $Domain = $_.Properties.distinguishedname.Split(',').where({$_ -like 'DC=*'})[0].TrimStart('DC=')
            $null = $MemberShip.Add("$Domain\$GroupName")
        })
        If ($MemberShip -notcontains "$DomainName\Domain Users")
        {
            $null = $MemberShip.Add("$DomainName\Domain Users")
            $DomainUsers = ([adsisearcher]"(&(objectCategory=group)(cn=Domain Users))").FindAll().Properties.distinguishedname
            ([adsisearcher]"(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:=$DomainUsers))").FindAll().ForEach({
                $GroupName = $_.Properties.samaccountname[0]
                $Domain = $_.Properties.distinguishedname.Split(',').where({$_ -like 'DC=*'})[0].TrimStart('DC=')
                $null = $MemberShip.Add("$Domain\$GroupName")
            })
        }
        $this.MemberOf = $MemberShip
        $this.SID = New-Object System.Security.Principal.SecurityIdentifier($Account.Properties.objectsid[0],0)
        $OU = $this.DistinguishedName.Split(',')[1..($this.DistinguishedName.Split(',').count - 1)] -join ','
        $ADOU = [adsi]"LDAP://$ADDomain/$OU"
        $this.ParentOU = $ADOU.properties.objectguid[0].ForEach({$_.ToString('x2')}) -join ''
    }

    RESWMUser ([string] $UserName, [string] $Domain)
    {
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $ADDomain = $forest.Domains | where Name -Like "$Domain.*"
        $ADSearcher = [adsisearcher]::new($ADDomain.GetDirectoryEntry(),"(&(objectClass=user)(SamAccountName=$UserName))")
        $ADSearcher.PropertiesToLoad.AddRange(@('name','distinguishedname','objectClass','memberof'))
        $Account = $ADSearcher.FindAll()
        $this.Name = $Account.Properties.name[0]
        $this.DistinguishedName = $Account.Properties.distinguishedname[0]
        $this.Domain = $Domain
        $MemberShip = New-Object System.Collections.ArrayList
        $Groups = [adsisearcher]"(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:=$($this.DistinguishedName)))"
        $Groups.FindAll().ForEach({
            $GroupName = $_.Properties.samaccountname[0]
            $DomainName = $_.Properties.distinguishedname.Split(',').where({$_ -like 'DC=*'})[0].TrimStart('DC=')
            $null = $MemberShip.Add("$DomainName\$GroupName")
        })
        If ($MemberShip -notcontains "$Domain\Domain Users")
        {
            $null = $MemberShip.Add("$Domain\Domain Users")
            $DomainUsers = ([adsisearcher]"(&(objectCategory=group)(cn=Domain Users))").FindAll().Properties.distinguishedname
            ([adsisearcher]"(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:=$DomainUsers))").FindAll().ForEach({
                $GroupName = $_.Properties.samaccountname[0]
                $DomainName = $_.Properties.distinguishedname.Split(',').where({$_ -like 'DC=*'})[0].TrimStart('DC=')
                $null = $MemberShip.Add("$DomainName\$GroupName")
            })
        }
        $this.MemberOf = $MemberShip
        $this.SID = New-Object System.Security.Principal.SecurityIdentifier($Account.Properties.objectsid[0],0)
        $OU = $this.DistinguishedName.Split(',')[1..($this.DistinguishedName.Split(',').count - 1)] -join ','
        $ADOU = [adsi]"LDAP://$ADDomain/$OU"
        $this.ParentOU = $ADOU.properties.objectguid[0].ForEach({$_.ToString('x2')}) -join ''
    }

    [string] ToString()
    {
        return $this.Domain + '\' + $this.Name
    }
}

# Application
class RESWMApplication
{
    [int]          $AppID
    [string]       $Title
    [string]       $Description
    [string]       $Path
    [bool]         $Enabled
    [bool]         $Hidden
    [string]       $CommandLine
    [string]       $Parameters
    [RESWMAccCtrl] $AccessControl
    [string]       $Type
    [XmlElement]   $FullObject
    hidden [guid]  $GUID
    hidden [guid]  $ParentGUID

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
        $this.Enabled = $XMLNode.recordenabled -eq 'yes'
        $this.Hidden = $XMLNode.config.application.settings.hidefrommenu -eq 'yes'
        $this.AppID = $XMLNode.AppID
        $this.Title = $XMLNode.config.application.configuration.title
        $this.Description = $XMLNode.config.application.configuration.description
        $this.CommandLine = $XMLNode.config.application.configuration.commandLine
        $this.Parameters = $XMLNode.config.application.configuration.parameters
        $this.AccessControl = $XMLNode.config.application.AccessControl
        switch -Wildcard ($XMLNode.config.application.configuration.commandline)
        {
            *\mstsc.exe    {If (!$this.Parameters -or 
                                $this.Parameters -match '^[-v|/v]')
                                {$this.Type = 'RDP'}}
            *\sfttray.exe  {$this.Type = 'AppV4'}
            %APPVPACK*     {$this.Type = 'AppV5'}
            \\*            {$this.Type = 'NetworkApp'}
            Default        {If ($this.Parameters -match 'https*\://' -or 
                                $this.CommandLine -match 'https*\://')
                            {$this.Type = 'URL'}
                            else{$this.Type = 'LocalApp'}
                           }
        }
        $this.FullObject = $XMLNode.config.application
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
        If ($this.ParentGUID -eq '00000000-0000-0000-0000-000000000000')
        {
            $this.Path = 'Start'
        }
        else
        {
            $this.Path = Get-RESWMStartMenu -GUID $this.ParentGUID
            If (!$this.Path)
            {          
                $this.Path = 'Disabled!'
            }
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
        foreach ($Property in [RESWMMenu].GetProperties().Name.where({$_ -notlike '*guid'}))
        {
            switch ($this.config.applicationmenu.$Property)
            {
                yes     {$this.$Property = $true}
                no      {$this.$Property = $false}
                default {$this.$Property = $XMLNode.config.applicationmenu.$Property}
            }
        }
        $this.Enabled = $XMLNode.recordenabled -eq 'yes'
        $this.GUID = $XMLNode.guid
        $this.ParentGUID = $XMLNode.parentguid
        $this.UpdateGUID = $XMLNode.updateGUID
        If ($XMLNode.parentguid -eq '{00000000-0000-0000-0000-000000000000}')
        {
            $this.Path = 'Start'
        }
        else
        {
            $SubFolder = Get-ChildItem WMCache: | sort LastWriteTime | select -Last 1 -ExpandProperty Name
            $MenuNode = (Select-Xml -Path WMCache:\$SubFolder\Objects\app_menus.xml -XPath "//objectinfo[guid = '$($XMLNode.guid)']").Node
            $arrPath = New-Object System.Collections.ArrayList
            Do
            {
                $MenuNode = (Select-Xml -Path WMCache:\$SubFolder\Objects\app_menus.xml -XPath "//objectinfo[guid = '$($MenuNode.parentguid)']").Node
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
    hidden [guid] $GUID
    hidden [guid] $UpdateGUID

    RESWMZone ([XmlElement] $XMLNode)
    {
        foreach ($Property in [RESWMZone].GetProperties().Name.where({$_ -notlike '*guid'}))
        {
            switch ($XMLNode.config.powerzone.$Property)
            {
                yes     {$this.$Property = $true}
                no      {$this.$Property = $false}
                default {$this.$Property = $XMLNode.config.powerzone.$Property}
            }
        }
        $this.Enabled = $XMLNode.recordenabled -eq 'yes'
        $this.GUID = $XMLNode.guid
        $this.UpdateGUID = $XMLNode.updateGUID
        $this.Rules = $XMLNode.config.powerzone.powerzonerules.rule
    }

    [string] ToString ()
    {
        return $this.Name
    }
}

# Access Control
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
            secrole   {$this.Access = $XMLNode.secroles.secrole.foreach({[RESWMAccess]::new('SecurityRole',$_)})}
            delegated {$this.Access = @($XMLNode.appmanlist.appmanglobal).foreach({
                                            [RESWMAccess]::new($_,'Delegated')})}
            ou        {$this.Access = $XMLNode.oufingerprint.ou}
            default   {$this.Access = $XMLNode.access}
        }
    }

    [string] ToString()
    {
        $Group = $this.Access | where type -NotMatch 'powerzone|clientname'
        $Zone = $this.Access | where type -Match 'powerzone|clientname'
        $AllGroups = $Group.ForEach({$_.ToString()}) -join " $($this.AccessMode.ToLower()) "
        $AllZones = $Zone.ForEach({$_.ToString()}) -join " $($this.ZoneMode.ToLower()) "
        If ($AllZones)
        {
            return "$AllGroups and $AllZones"
        }
        else
        {
            return $AllGroups
        }
    }
}

# Access
class RESWMAccess
{
    [string]   $Type
    [psobject] $Object
    [string]   $SID
    [string]   $Options

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
            clientname     {$this.Object = If ($XMLNode.object){$XMLNode.object}else{$XMLNode.InnerText}}
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

    RESWMAccess ([string] $Type, [guid] $GUID)
    {
        $this.Type = $Type
        switch ($Type)
        {
            SecurityRole {$this.object = Get-RESWMSecurityRole -GUID $GUID}
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
            clientname     {$String = "Client: [$($this.Object)]"}
            default        {$String = "[$($this.Object)]"}
        }
        return $String
    }
}

#Security Role
class RESWMSecRole
{
    [string]      $Name
    [string]      $Description
    [XmlNode]     $Nodes
    [RESWMZone[]] $PowerZones
    [XmlNode]     $Scope
    [RESWMAccCtrl] $AccessControl
    hidden [GUID] $GUID
    hidden [GUID] $UpdateGUID
    [bool] $Enabled

    RESWMSecRole ([XmlElement] $XMLNode)
    {
        foreach ($Property in [RESWMSecRole].GetProperties().Name.where({$_ -notlike '*guid'}))
        {
            switch ($Property)
            {
                Name {$this.Name = $XMLNode.objectdesc}
                Enabled {$this.Enabled = $XMLNode.recordenabled -eq 'yes'}
                default {If ($XMLNode.config.securityroles.$Property){
                            $this.$Property = $XMLNode.config.securityroles.$Property}
                        }
            }
        }
    }
}

# Drive Mapping
class RESWMMapping #Scope
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
    [string] $Scope
    hidden [int]  $Order
    hidden [guid] $GUID
    hidden [guid] $UpdateGUID
    hidden [guid] $ParentGUID

    RESWMMapping ([XmlElement] $XMLNode)
    {
        foreach ($Property in [RESWMMapping].GetProperties().Name.where({$_ -notlike '*guid'}))
        {
            switch ($XMLNode.config.mapping.$Property)
            {
                yes     {$this.$Property = $true}
                no      {$this.$Property = $false}
                default {$this.$Property = $XMLNode.config.mapping.$Property}
            }
        }
        $this.Enabled = $XMLNode.recordenabled -eq 'yes'
        $this.GUID = $XMLNode.guid
        $this.ParentGUID = $XMLNode.parentguid
        $this.UpdateGUID = $XMLNode.updateGUID
        switch ($this.ParentGuid)
        {
            ([guid]::Empty) {$this.Scope = 'Global'}
            default {$this.Scope = 'Application'}
        }
    }

    [string] ToString()
    {
        return $this.ShareName
    }
}

# User Preference (Zero-Profile)
class RESWMUserPref
{
    [string] $Name
    [string] $Description
    [bool]   $Enabled
    [RESWMAccCtrl] $AccessControl
    [psobject] $Settings
    [psobject] $Exclusions
    [string] $Location
    hidden [guid]   $GUID
    hidden [guid]   $UpdateGuid
    hidden [guid]   $ParentGuid
    hidden [string] $ObjectDesc

    RESWMUserPref ([XmlElement] $XMLNode)
    {
        foreach ($Property in [RESWMUserPref].GetProperties().Name.where({$_ -notlike '*guid'}))
        {
            switch ($XMLNode.config.profile.$Property)
            {
                yes     {$this.$Property = $true}
                no      {$this.$Property = $false}
                default {$this.$Property = $XMLNode.config.profile.$Property}
            }
        }
        $this.Enabled = $XMLNode.recordenabled -eq 'yes'
        $this.GUID = $XMLNode.guid
        $this.ParentGUID = $XMLNode.parentguid
        $this.UpdateGUID = $XMLNode.updateGUID
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

class RESWMRegistry #Scope
{
    [int]          $Order
    [string]       $Name
    [string]       $Description
    [RESWMAccCtrl] $AccessControl
    [bool]         $Enabled
    [string]       $Type
    [string]       $Scope
    [Registry[]]   $Registry
    [string]       $State
    [string]       $ObjectDesc
    [bool]         $Runonce
    [string]       $RunonceFile
    hidden [guid]  $ParentGuid
    hidden [guid]  $GUID
    hidden [guid]  $UpdateGuid
    hidden [string]$File

    RESWMRegistry ([XmlElement] $XMLNode)
    {
        foreach ($Property in [RESWMRegistry].GetProperties().Name.where({$_ -notlike '*guid'}))
        {
            switch ($XMLNode.config.registry.$Property)
            {
                yes     {$this.$Property = $true}
                no      {$this.$Property = $false}
                default {$this.$Property = $XMLNode.config.registry.$Property}
            }
        }
        $this.Enabled = $XMLNode.recordenabled -eq 'yes'
        $this.GUID = $XMLNode.guid
        $this.Order = $XMLNode.order
        $this.ParentGUID = $XMLNode.parentguid
        $this.UpdateGUID = $XMLNode.updateGUID
        switch ($this.ParentGuid)
        {
            ([guid]::Empty) {$this.Scope = 'Global'}
            default {$this.Scope = 'Application'}
        }
        $this.File = $XMLNode.config.registry.registryfile
        $this.Registry = Get-WMREGFile $this.File
        If (!$this.State)
        {
            $this.State = 'Both'
        }
    }

    # Show content of the Registry file
    [string[]] GetRegfileContent()
    {
        return (Get-WMREGFile $this.File -ShowContent)
    }

    [System.IO.FileInfo] SaveRegfile ([string]$Path)
    {
        return (Get-WMREGFile $this.File -SaveFile $Path)
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

    [string] ToString()
    {
        return $this.Value
    }
}

# Printer
class RESWMPrinter #scope
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
    [string] $Scope
    hidden [guid] $GUID
    hidden [guid] $ParentGUID
    hidden [guid] $UpdateGUID
    #$objectdesc

    RESWMPrinter ([XmlElement] $XMLNode)
    {
        foreach ($Property in [RESWMPrinter].GetProperties().Name.where({$_ -notlike '*guid'}))
        {
            switch ($XMLNode.config.printermapping.$Property)
            {
                yes     {$this.$Property = $true}
                no      {$this.$Property = $false}
                default {$this.$Property = $XMLNode.config.printermapping.$Property}
            }
        }
        $this.Enabled = $XMLNode.recordenabled -eq 'yes'
        $this.GUID = $XMLNode.guid
        $this.ParentGUID = $XMLNode.parentguid
        $this.UpdateGUID = $XMLNode.updateGUID
        switch ($this.ParentGuid)
        {
            ([guid]::Empty) {$this.Scope = 'Global'}
            default {$this.Scope = 'Application'}
        }
    }

    [string] ToString ()
    {
        return $this.Printer
    }
}

# Variable
class RESWMVariable #Scope
{
    [int]    $Order
    [string] $Name
    [string] $Description
    [string] $Value
    [RESWMAccCtrl] $AccessControl
    [bool]   $Enabled
    [string] $State
    [string] $Scope
    hidden [guid] $GUID
    hidden [guid] $ParentGUID
    hidden [guid] $UpdateGUID

    RESWMVariable ([XmlElement] $XMLNode)
    {
        foreach ($Property in [RESWMVariable].GetProperties().Name.where({$_ -notlike '*guid'}))
        {
            switch ($XMLNode.config.variable.$Property)
            {
                yes     {$this.$Property = $true}
                no      {$this.$Property = $false}
                default {$this.$Property = $XMLNode.config.variable.$Property}
            }
        }
        $this.Enabled = $XMLNode.recordenabled -eq 'yes'
        $this.GUID = $XMLNode.guid
        $this.ParentGUID = $XMLNode.parentguid
        $this.UpdateGUID = $XMLNode.updateGUID
        $this.Order = $XMLNode.order
        switch ($this.ParentGuid)
        {
            ([guid]::Empty) {$this.Scope = 'Global'}
            default {$this.Scope = 'Application'}
        }
    }

    [string] ToString ()
    {
        return $this.Name
    }
}

# Task
class RESWMTask #Scope
{
    [int]    $Order
    [string] $Description
    [string] $CommandLine
    [string] $Script
    [string] $Extension
    [RESWMAccCtrl] $AccessControl
    [bool]   $WaitForApplication
    [bool]   $Enabled
    [string] $State
    [string] $Scope
    hidden [guid] $GUID
    hidden [guid] $ParentGUID
    hidden [guid] $UpdateGUID

    RESWMVariable ([XmlElement] $XMLNode)
    {
        foreach ($Property in [RESWMVariable].GetProperties().Name.where({$_ -notlike '*guid'}))
        {
            switch ($XMLNode.config.variable.$Property)
            {
                yes     {$this.$Property = $true}
                no      {$this.$Property = $false}
                default {$this.$Property = $XMLNode.config.variable.$Property}
            }
        }
        $this.Enabled = $XMLNode.recordenabled -eq 'yes'
        $this.GUID = $XMLNode.guid
        $this.Extension = $XMLNode.scriptext
        $this.ParentGUID = $XMLNode.parentguid
        $this.UpdateGUID = $XMLNode.updateGUID
        $this.Order = $XMLNode.order
        switch ($this.ParentGuid)
        {
            ([guid]::Empty) {$this.Scope = 'Global'}
            default {$this.Scope = 'Application'}
        }
    }

    [string] ToString ()
    {
        return $this.Name
    }
}

#endregion Classes
