#
# Module manifest for module 'RESWM'
#
# Generated by: Michaja van der Zouwen
#
# Generated on: 20-11-2018
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'RESWM.psm1'

# Version number of this module.
ModuleVersion = '1.0'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = 'cfc715e1-8a62-4833-9b9d-745308b42b36'

# Author of this module
Author = 'Michaja van der Zouwen'

# Company or vendor of this module
CompanyName = 'ITMicaH'

# Copyright statement for this module
Copyright = '(c) 2018 Michaja van der Zouwen. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Module for RES One Workspace'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.0'

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
ScriptsToProcess = @('RESWM-Classes.ps1')

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @(
    'Connect-RESWMRelayServer',
    'Get-RESWMApplication',  
    'Get-RESWMMapping',          
    'Get-RESWMPrinter',
    'Get-RESWMRegistry',
    'Get-RESWMSecurityRole',
    'Get-RESWMStartMenu',
    'Get-RESWMTask',
    'Get-RESWMUserPreference',
    'Get-RESWMUserPreferenceFiles',
    'Get-RESWMVariable',
    'Get-RESWMZone',
    'Reset-RESWMUserPreference',
    'Update-RESWMAgentCache'
)

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = '*'

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = '*'

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        # Tags = @()

        # A URL to the license for this module.
        # LicenseUri = ''

        # A URL to the main website for this project.
        # ProjectUri = ''

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        # ReleaseNotes = ''

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

