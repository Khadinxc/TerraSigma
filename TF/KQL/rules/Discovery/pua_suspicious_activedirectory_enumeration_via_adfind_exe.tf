resource "azurerm_sentinel_alert_rule_scheduled" "pua_suspicious_activedirectory_enumeration_via_adfind_exe" {
  name                       = "pua_suspicious_activedirectory_enumeration_via_adfind_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE"
  description                = "Detects active directory enumeration activity using known AdFind CLI flags - Authorized administrative activity"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "-sc admincountdmp" or ProcessCommandLine contains "-sc exchaddresses" or (ProcessCommandLine contains "lockoutduration" or ProcessCommandLine contains "lockoutthreshold" or ProcessCommandLine contains "lockoutobservationwindow" or ProcessCommandLine contains "maxpwdage" or ProcessCommandLine contains "minpwdage" or ProcessCommandLine contains "minpwdlength" or ProcessCommandLine contains "pwdhistorylength" or ProcessCommandLine contains "pwdproperties")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1087"]
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