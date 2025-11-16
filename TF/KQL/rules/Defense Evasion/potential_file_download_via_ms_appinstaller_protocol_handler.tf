resource "azurerm_sentinel_alert_rule_scheduled" "potential_file_download_via_ms_appinstaller_protocol_handler" {
  name                       = "potential_file_download_via_ms_appinstaller_protocol_handler"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential File Download Via MS-AppInstaller Protocol Handler"
  description                = "Detects usage of the \"ms-appinstaller\" protocol handler via command line to potentially download arbitrary files via AppInstaller.EXE The downloaded files are temporarly stored in \":\\Users\\%username%\\AppData\\Local\\Packages\\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\\AC\\INetCache\\<RANDOM-8-CHAR-DIRECTORY>\""
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "ms-appinstaller://" and ProcessCommandLine contains "source=") and ProcessCommandLine contains "http"
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
  }
}