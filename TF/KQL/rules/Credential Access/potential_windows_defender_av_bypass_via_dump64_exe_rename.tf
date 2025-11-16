resource "azurerm_sentinel_alert_rule_scheduled" "potential_windows_defender_av_bypass_via_dump64_exe_rename" {
  name                       = "potential_windows_defender_av_bypass_via_dump64_exe_rename"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Windows Defender AV Bypass Via Dump64.EXE Rename"
  description                = "Detects when a user is potentially trying to bypass the Windows Defender AV by renaming a tool to dump64.exe and placing it in the Visual Studio folder. Currently the rule is covering only usage of procdump but other utilities can be added in order to increase coverage."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath contains "\\Microsoft Visual Studio\\" and FolderPath endswith "\\dump64.exe" and FolderPath startswith ":\\Program Files") and (ProcessVersionInfoOriginalFileName =~ "procdump" or (ProcessCommandLine contains " -ma " or ProcessCommandLine contains " -mp "))
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