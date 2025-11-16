resource "azurerm_sentinel_alert_rule_scheduled" "lsass_process_reconnaissance_via_findstr_exe" {
  name                       = "lsass_process_reconnaissance_via_findstr_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "LSASS Process Reconnaissance Via Findstr.EXE"
  description                = "Detects findstring commands that include the keyword lsass, which indicates recon actviity for the LSASS process PID"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "lsass" and ((FolderPath endswith "\\find.exe" or FolderPath endswith "\\findstr.exe") or (ProcessVersionInfoOriginalFileName in~ ("FIND.EXE", "FINDSTR.EXE")))) or (ProcessCommandLine contains " -i \"lsass" or ProcessCommandLine contains " /i \"lsass" or ProcessCommandLine contains " –i \"lsass" or ProcessCommandLine contains " —i \"lsass" or ProcessCommandLine contains " ―i \"lsass" or ProcessCommandLine contains " -i lsass.exe" or ProcessCommandLine contains " /i lsass.exe" or ProcessCommandLine contains " –i lsass.exe" or ProcessCommandLine contains " —i lsass.exe" or ProcessCommandLine contains " ―i lsass.exe" or ProcessCommandLine contains "findstr \"lsass" or ProcessCommandLine contains "findstr lsass" or ProcessCommandLine contains "findstr.exe \"lsass" or ProcessCommandLine contains "findstr.exe lsass")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1552"]
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