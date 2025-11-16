resource "azurerm_sentinel_alert_rule_scheduled" "group_membership_reconnaissance_via_whoami_exe" {
  name                       = "group_membership_reconnaissance_via_whoami_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Group Membership Reconnaissance Via Whoami.EXE"
  description                = "Detects the execution of whoami.exe with the /group command line flag to show group membership for the current user, account type, security identifiers (SID), and attributes."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " /groups" or ProcessCommandLine contains " -groups") and (FolderPath endswith "\\whoami.exe" or ProcessVersionInfoOriginalFileName =~ "whoami.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1033"]
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