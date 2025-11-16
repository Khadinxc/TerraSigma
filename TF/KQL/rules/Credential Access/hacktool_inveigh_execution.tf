resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_inveigh_execution" {
  name                       = "hacktool_inveigh_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - Inveigh Execution"
  description                = "Detects the use of Inveigh a cross-platform .NET IPv4/IPv6 machine-in-the-middle tool - Very unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\Inveigh.exe" or (ProcessVersionInfoOriginalFileName in~ ("\\Inveigh.exe", "\\Inveigh.dll")) or ProcessVersionInfoFileDescription =~ "Inveigh" or (ProcessCommandLine contains " -SpooferIP" or ProcessCommandLine contains " -ReplyToIPs " or ProcessCommandLine contains " -ReplyToDomains " or ProcessCommandLine contains " -ReplyToMACs " or ProcessCommandLine contains " -SnifferIP")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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