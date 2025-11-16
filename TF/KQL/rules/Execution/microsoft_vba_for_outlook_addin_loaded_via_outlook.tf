resource "azurerm_sentinel_alert_rule_scheduled" "microsoft_vba_for_outlook_addin_loaded_via_outlook" {
  name                       = "microsoft_vba_for_outlook_addin_loaded_via_outlook"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Microsoft VBA For Outlook Addin Loaded Via Outlook"
  description                = "Detects outlvba (Microsoft VBA for Outlook Addin) DLL being loaded by the outlook process - Legitimate macro usage. Add the appropriate filter according to your environment"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath endswith "\\outlvba.dll" and InitiatingProcessFolderPath endswith "\\outlook.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1204"]
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