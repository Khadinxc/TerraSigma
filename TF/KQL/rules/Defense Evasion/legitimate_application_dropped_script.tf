resource "azurerm_sentinel_alert_rule_scheduled" "legitimate_application_dropped_script" {
  name                       = "legitimate_application_dropped_script"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Legitimate Application Dropped Script"
  description                = "Detects programs on a Windows system that should not write scripts to disk"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath endswith "\\eqnedt32.exe" or InitiatingProcessFolderPath endswith "\\wordpad.exe" or InitiatingProcessFolderPath endswith "\\wordview.exe" or InitiatingProcessFolderPath endswith "\\certutil.exe" or InitiatingProcessFolderPath endswith "\\certoc.exe" or InitiatingProcessFolderPath endswith "\\CertReq.exe" or InitiatingProcessFolderPath endswith "\\Desktopimgdownldr.exe" or InitiatingProcessFolderPath endswith "\\esentutl.exe" or InitiatingProcessFolderPath endswith "\\mshta.exe" or InitiatingProcessFolderPath endswith "\\AcroRd32.exe" or InitiatingProcessFolderPath endswith "\\RdrCEF.exe" or InitiatingProcessFolderPath endswith "\\hh.exe" or InitiatingProcessFolderPath endswith "\\finger.exe") and (FolderPath endswith ".ps1" or FolderPath endswith ".bat" or FolderPath endswith ".vbs" or FolderPath endswith ".scf" or FolderPath endswith ".wsf" or FolderPath endswith ".wsh")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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