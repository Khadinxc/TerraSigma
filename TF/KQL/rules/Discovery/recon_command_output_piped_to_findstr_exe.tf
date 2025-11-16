resource "azurerm_sentinel_alert_rule_scheduled" "recon_command_output_piped_to_findstr_exe" {
  name                       = "recon_command_output_piped_to_findstr_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Recon Command Output Piped To Findstr.EXE"
  description                = "Detects the execution of a potential recon command where the results are piped to \"findstr\". This is meant to trigger on inline calls of \"cmd.exe\" via the \"/c\" or \"/k\" for example. Attackers often time use this technique to extract specific information they require in their reconnaissance phase."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "ipconfig" and ProcessCommandLine contains "|" and ProcessCommandLine contains "find") or (ProcessCommandLine contains "net" and ProcessCommandLine contains "|" and ProcessCommandLine contains "find") or (ProcessCommandLine contains "netstat" and ProcessCommandLine contains "|" and ProcessCommandLine contains "find") or (ProcessCommandLine contains "ping" and ProcessCommandLine contains "|" and ProcessCommandLine contains "find") or (ProcessCommandLine contains "systeminfo" and ProcessCommandLine contains "|" and ProcessCommandLine contains "find") or (ProcessCommandLine contains "tasklist" and ProcessCommandLine contains "|" and ProcessCommandLine contains "find") or (ProcessCommandLine contains "whoami" and ProcessCommandLine contains "|" and ProcessCommandLine contains "find")) and (not((ProcessCommandLine contains "cmd.exe /c TASKLIST /V |" and ProcessCommandLine contains "FIND /I" and ProcessCommandLine contains "\\xampp\\" and ProcessCommandLine contains "\\catalina_start.bat")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1057"]
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