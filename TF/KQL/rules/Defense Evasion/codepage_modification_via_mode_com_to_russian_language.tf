resource "azurerm_sentinel_alert_rule_scheduled" "codepage_modification_via_mode_com_to_russian_language" {
  name                       = "codepage_modification_via_mode_com_to_russian_language"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "CodePage Modification Via MODE.COM To Russian Language"
  description                = "Detects a CodePage modification using the \"mode.com\" utility to Russian language. This behavior has been used by threat actors behind Dharma ransomware. - Russian speaking people changing the CodePage"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " con " and ProcessCommandLine contains " cp " and ProcessCommandLine contains " select=") and (ProcessCommandLine endswith "=1251" or ProcessCommandLine endswith "=866")) and (FolderPath endswith "\\mode.com" or ProcessVersionInfoOriginalFileName =~ "MODE.COM")
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