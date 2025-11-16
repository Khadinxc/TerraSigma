resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_remotekrbrelay_execution" {
  name                       = "hacktool_remotekrbrelay_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - RemoteKrbRelay Execution"
  description                = "Detects the use of RemoteKrbRelay, a Kerberos relaying tool via CommandLine flags and PE metadata. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\RemoteKrbRelay.exe" or ProcessVersionInfoOriginalFileName =~ "RemoteKrbRelay.exe") or (ProcessCommandLine contains " -clsid " and ProcessCommandLine contains " -target " and ProcessCommandLine contains " -victim ") or (ProcessCommandLine contains "-rbcd " and (ProcessCommandLine contains "-cn " or ProcessCommandLine contains "--computername ")) or (ProcessCommandLine contains "-chp " and (ProcessCommandLine contains "-chpPass " and ProcessCommandLine contains "-chpUser ")) or (ProcessCommandLine contains "-addgroupmember " and ProcessCommandLine contains "-group " and ProcessCommandLine contains "-groupuser ") or ((ProcessCommandLine contains "interactive" or ProcessCommandLine contains "secrets" or ProcessCommandLine contains "service-add") and (ProcessCommandLine contains "-smb " and ProcessCommandLine contains "--smbkeyword "))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1558"]
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