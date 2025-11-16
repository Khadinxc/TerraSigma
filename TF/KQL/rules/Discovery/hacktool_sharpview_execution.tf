resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_sharpview_execution" {
  name                       = "hacktool_sharpview_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - SharpView Execution"
  description                = "Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessVersionInfoOriginalFileName =~ "SharpView.exe" or FolderPath endswith "\\SharpView.exe" or (ProcessCommandLine contains "Add-RemoteConnection" or ProcessCommandLine contains "Convert-ADName" or ProcessCommandLine contains "ConvertFrom-SID" or ProcessCommandLine contains "ConvertFrom-UACValue" or ProcessCommandLine contains "Convert-SidToName" or ProcessCommandLine contains "Export-PowerViewCSV" or ProcessCommandLine contains "Find-DomainObjectPropertyOutlier" or ProcessCommandLine contains "Find-DomainProcess" or ProcessCommandLine contains "Find-DomainShare" or ProcessCommandLine contains "Find-DomainUserEvent" or ProcessCommandLine contains "Find-DomainUserLocation" or ProcessCommandLine contains "Find-ForeignGroup" or ProcessCommandLine contains "Find-ForeignUser" or ProcessCommandLine contains "Find-GPOComputerAdmin" or ProcessCommandLine contains "Find-GPOLocation" or ProcessCommandLine contains "Find-Interesting" or ProcessCommandLine contains "Find-LocalAdminAccess" or ProcessCommandLine contains "Find-ManagedSecurityGroups" or ProcessCommandLine contains "Get-CachedRDPConnection" or ProcessCommandLine contains "Get-DFSshare" or ProcessCommandLine contains "Get-DomainComputer" or ProcessCommandLine contains "Get-DomainController" or ProcessCommandLine contains "Get-DomainDFSShare" or ProcessCommandLine contains "Get-DomainDNSRecord" or ProcessCommandLine contains "Get-DomainFileServer" or ProcessCommandLine contains "Get-DomainForeign" or ProcessCommandLine contains "Get-DomainGPO" or ProcessCommandLine contains "Get-DomainGroup" or ProcessCommandLine contains "Get-DomainGUIDMap" or ProcessCommandLine contains "Get-DomainManagedSecurityGroup" or ProcessCommandLine contains "Get-DomainObject" or ProcessCommandLine contains "Get-DomainOU" or ProcessCommandLine contains "Get-DomainPolicy" or ProcessCommandLine contains "Get-DomainSID" or ProcessCommandLine contains "Get-DomainSite" or ProcessCommandLine contains "Get-DomainSPNTicket" or ProcessCommandLine contains "Get-DomainSubnet" or ProcessCommandLine contains "Get-DomainTrust" or ProcessCommandLine contains "Get-DomainUserEvent" or ProcessCommandLine contains "Get-ForestDomain" or ProcessCommandLine contains "Get-ForestGlobalCatalog" or ProcessCommandLine contains "Get-ForestTrust" or ProcessCommandLine contains "Get-GptTmpl" or ProcessCommandLine contains "Get-GroupsXML" or ProcessCommandLine contains "Get-LastLoggedOn" or ProcessCommandLine contains "Get-LoggedOnLocal" or ProcessCommandLine contains "Get-NetComputer" or ProcessCommandLine contains "Get-NetDomain" or ProcessCommandLine contains "Get-NetFileServer" or ProcessCommandLine contains "Get-NetForest" or ProcessCommandLine contains "Get-NetGPO" or ProcessCommandLine contains "Get-NetGroupMember" or ProcessCommandLine contains "Get-NetLocalGroup" or ProcessCommandLine contains "Get-NetLoggedon" or ProcessCommandLine contains "Get-NetOU" or ProcessCommandLine contains "Get-NetProcess" or ProcessCommandLine contains "Get-NetRDPSession" or ProcessCommandLine contains "Get-NetSession" or ProcessCommandLine contains "Get-NetShare" or ProcessCommandLine contains "Get-NetSite" or ProcessCommandLine contains "Get-NetSubnet" or ProcessCommandLine contains "Get-NetUser" or ProcessCommandLine contains "Get-PathAcl" or ProcessCommandLine contains "Get-PrincipalContext" or ProcessCommandLine contains "Get-RegistryMountedDrive" or ProcessCommandLine contains "Get-RegLoggedOn" or ProcessCommandLine contains "Get-WMIRegCachedRDPConnection" or ProcessCommandLine contains "Get-WMIRegLastLoggedOn" or ProcessCommandLine contains "Get-WMIRegMountedDrive" or ProcessCommandLine contains "Get-WMIRegProxy" or ProcessCommandLine contains "Invoke-ACLScanner" or ProcessCommandLine contains "Invoke-CheckLocalAdminAccess" or ProcessCommandLine contains "Invoke-Kerberoast" or ProcessCommandLine contains "Invoke-MapDomainTrust" or ProcessCommandLine contains "Invoke-RevertToSelf" or ProcessCommandLine contains "Invoke-Sharefinder" or ProcessCommandLine contains "Invoke-UserImpersonation" or ProcessCommandLine contains "Remove-DomainObjectAcl" or ProcessCommandLine contains "Remove-RemoteConnection" or ProcessCommandLine contains "Request-SPNTicket" or ProcessCommandLine contains "Set-DomainObject" or ProcessCommandLine contains "Test-AdminAccess")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1049", "T1069", "T1482", "T1135", "T1033"]
  enabled                    = true

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = false
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "AllEntities"
      by_entities             = []
      by_alert_details        = []
      by_custom_details       = []
    }
  }

  event_grouping {
    aggregation_method = "SingleAlert"
  }

  entity_mapping {
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
    field_mapping {
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}