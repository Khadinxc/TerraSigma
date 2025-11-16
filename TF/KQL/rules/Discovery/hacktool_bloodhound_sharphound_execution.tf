resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_bloodhound_sharphound_execution" {
  name                       = "hacktool_bloodhound_sharphound_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - Bloodhound/Sharphound Execution"
  description                = "Detects command line parameters used by Bloodhound and Sharphound hack tools - Other programs that use these command line option and accepts an 'All' parameter"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -CollectionMethod All " or ProcessCommandLine contains " --CollectionMethods Session " or ProcessCommandLine contains " --Loop --Loopduration " or ProcessCommandLine contains " --PortScanTimeout " or ProcessCommandLine contains ".exe -c All -d " or ProcessCommandLine contains "Invoke-Bloodhound" or ProcessCommandLine contains "Get-BloodHoundData") or (ProcessCommandLine contains " -JsonFolder " and ProcessCommandLine contains " -ZipFileName ") or (ProcessCommandLine contains " DCOnly " and ProcessCommandLine contains " --NoSaveCache ") or (ProcessVersionInfoProductName contains "SharpHound" or ProcessVersionInfoFileDescription contains "SharpHound" or (ProcessVersionInfoCompanyName contains "SpecterOps" or ProcessVersionInfoCompanyName contains "evil corp") or (FolderPath contains "\\Bloodhound.exe" or FolderPath contains "\\SharpHound.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery", "Execution"]
  techniques                 = ["T1087", "T1482", "T1069", "T1059"]
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