resource "azurerm_sentinel_alert_rule_scheduled" "lazarus_group_activity" {
  name                       = "lazarus_group_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Lazarus Group Activity"
  description                = "Detects different process execution behaviors as described in various threat reports on Lazarus group activity - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "reg.exe save hklm\\sam %temp%\\~reg_sam.save" or ProcessCommandLine contains "1q2w3e4r@#$@#$@#$" or ProcessCommandLine contains " -hp1q2w3e4 " or ProcessCommandLine contains ".dat data03 10000 -p ") or (ProcessCommandLine contains "netstat -aon | find " and ProcessCommandLine contains "ESTA" and ProcessCommandLine contains " > %temp%\\~") or (ProcessCommandLine contains ".255 10 C:\\ProgramData\\IBM\\" and ProcessCommandLine contains ".DAT") or ((ProcessCommandLine contains "C:\\ProgramData\\" or ProcessCommandLine contains "C:\\RECYCLER\\") and (ProcessCommandLine contains " /c " and ProcessCommandLine contains " -p 0x")) or ((ProcessCommandLine contains ".bin," or ProcessCommandLine contains ".tmp," or ProcessCommandLine contains ".dat," or ProcessCommandLine contains ".io," or ProcessCommandLine contains ".ini," or ProcessCommandLine contains ".db,") and (ProcessCommandLine contains "rundll32 " and ProcessCommandLine contains "C:\\ProgramData\\"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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
  }
}