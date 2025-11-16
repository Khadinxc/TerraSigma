resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_new_instance_of_an_office_com_object" {
  name                       = "suspicious_new_instance_of_an_office_com_object"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious New Instance Of An Office COM Object"
  description                = "Detects an svchost process spawning an instance of an office application. This happens when the initial word application creates an instance of one of the Office COM objects such as 'Word.Application', 'Excel.Application', etc. This can be used by malicious actors to create malicious Office documents with macros on the fly. (See vba2clr project in the references) - Legitimate usage of office automation via scripting"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\eqnedt32.exe" or FolderPath endswith "\\excel.exe" or FolderPath endswith "\\msaccess.exe" or FolderPath endswith "\\mspub.exe" or FolderPath endswith "\\powerpnt.exe" or FolderPath endswith "\\visio.exe" or FolderPath endswith "\\winword.exe") and InitiatingProcessFolderPath endswith "\\svchost.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
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