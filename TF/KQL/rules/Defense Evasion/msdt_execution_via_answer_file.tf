resource "azurerm_sentinel_alert_rule_scheduled" "msdt_execution_via_answer_file" {
  name                       = "msdt_execution_via_answer_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "MSDT Execution Via Answer File"
  description                = "Detects execution of \"msdt.exe\" using an answer file which is simulating the legitimate way of calling msdt via \"pcwrun.exe\" (For example from the compatibility tab). - Possible undocumented parents of \"msdt\" other than \"pcwrun\"."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "\\WINDOWS\\diagnostics\\index\\PCWDiagnostic.xml" and (ProcessCommandLine contains " -af " or ProcessCommandLine contains " /af " or ProcessCommandLine contains " –af " or ProcessCommandLine contains " —af " or ProcessCommandLine contains " ―af ") and FolderPath endswith "\\msdt.exe") and (not(InitiatingProcessFolderPath endswith "\\pcwrun.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
  techniques                 = ["T1218"]
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
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}