#region Classes

Using namespace  System.Xml

class RESWMApplication
{
    [bool]       $Enabled
    [int]        $AppID
    [string]     $Title
    [string]     $Description
    [string]     $CommandLine
    [string]     $Parameters
    [RESWMAccCtrl] $AccessControl
    [string]     $Type
    [XmlElement] $FullObject
    hidden [guid] $GUID

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
    }
}

class RESWMZone
{
    [string] $Name
    [string] $Description
    [object] $Rules
    [guid]   $Guid
    [bool]   $Enabled
    [string] $ObjectDesc
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
            secrole   {}
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
    [bool] $System

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
    [string] $Path
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

}

class RESWMUserPref
{
    [string] $ConfigView
    [string] $Name
    [string] $Description
    [RESWMAccCtrl] $AccessControl
    [psobject] $Settings
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
            switch ($this.$Property)
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
    }
}

class RESWMRegistry
{
    [string]       $Name
    [string]       $Description
    [RESWMAccCtrl] $AccessControl
    [bool]         $Enabled
    [string]       $Type
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
            switch ($this.$Property)
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
    }
}

#endregion Classes