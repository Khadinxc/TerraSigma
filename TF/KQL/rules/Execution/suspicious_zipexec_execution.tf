resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_zipexec_execution" {
  name                       = "suspicious_zipexec_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious ZipExec Execution"
  description                = "ZipExec is a Proof-of-Concept (POC) tool to wrap binary-based tools into a password-protected zip file."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "/generic:Microsoft_Windows_Shell_ZipFolder:filename=" and ProcessCommandLine contains ".zip" and ProcessCommandLine contains "/pass:" and ProcessCommandLine contains "/user:") or (ProcessCommandLine contains "/delete" and ProcessCommandLine contains "Microsoft_Windows_Shell_ZipFolder:filename=" and ProcessCommandLine contains ".zip")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1218", "T1202"]
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
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
  }
}