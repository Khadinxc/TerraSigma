resource "azurerm_sentinel_alert_rule_scheduled" "renamed_procdump_execution" {
  name                       = "renamed_procdump_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Renamed ProcDump Execution"
  description                = "Detects the execution of a renamed ProcDump executable. This often done by attackers or malware in order to evade defensive mechanisms. - Procdump illegally bundled with legitimate software. - Administrators who rename binaries (should be investigated)."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessVersionInfoOriginalFileName =~ "procdump" or ((ProcessCommandLine contains " -ma " or ProcessCommandLine contains " /ma " or ProcessCommandLine contains " –ma " or ProcessCommandLine contains " —ma " or ProcessCommandLine contains " ―ma " or ProcessCommandLine contains " -mp " or ProcessCommandLine contains " /mp " or ProcessCommandLine contains " –mp " or ProcessCommandLine contains " —mp " or ProcessCommandLine contains " ―mp ") and (ProcessCommandLine contains " -accepteula" or ProcessCommandLine contains " /accepteula" or ProcessCommandLine contains " –accepteula" or ProcessCommandLine contains " —accepteula" or ProcessCommandLine contains " ―accepteula"))) and (not((FolderPath endswith "\\procdump.exe" or FolderPath endswith "\\procdump64.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036"]
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