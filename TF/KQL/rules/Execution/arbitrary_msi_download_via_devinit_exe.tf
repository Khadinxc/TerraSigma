resource "azurerm_sentinel_alert_rule_scheduled" "arbitrary_msi_download_via_devinit_exe" {
  name                       = "arbitrary_msi_download_via_devinit_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Arbitrary MSI Download Via Devinit.EXE"
  description                = "Detects a certain command line flag combination used by \"devinit.exe\", which can be abused as a LOLBIN to download arbitrary MSI packages on a Windows system"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains " -t msi-install " and ProcessCommandLine contains " -i http"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
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
  }
}