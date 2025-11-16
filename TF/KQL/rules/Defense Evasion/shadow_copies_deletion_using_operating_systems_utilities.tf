resource "azurerm_sentinel_alert_rule_scheduled" "shadow_copies_deletion_using_operating_systems_utilities" {
  name                       = "shadow_copies_deletion_using_operating_systems_utilities"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Shadow Copies Deletion Using Operating Systems Utilities"
  description                = "Shadow Copies deletion using operating systems utilities - Legitimate Administrator deletes Shadow Copies using operating systems utilities for legitimate reason - LANDesk LDClient Ivanti-PSModule (PS EncodedCommand)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "shadow" and ProcessCommandLine contains "delete") and ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\wmic.exe" or FolderPath endswith "\\vssadmin.exe" or FolderPath endswith "\\diskshadow.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll", "wmic.exe", "VSSADMIN.EXE", "diskshadow.exe")))) or ((ProcessCommandLine contains "delete" and ProcessCommandLine contains "catalog" and ProcessCommandLine contains "quiet") and (FolderPath endswith "\\wbadmin.exe" or ProcessVersionInfoOriginalFileName =~ "WBADMIN.EXE")) or (((ProcessCommandLine contains "unbounded" or ProcessCommandLine contains "/MaxSize=") and (ProcessCommandLine contains "resize" and ProcessCommandLine contains "shadowstorage")) and (FolderPath endswith "\\vssadmin.exe" or ProcessVersionInfoOriginalFileName =~ "VSSADMIN.EXE"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Impact"]
  techniques                 = ["T1070", "T1490"]
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