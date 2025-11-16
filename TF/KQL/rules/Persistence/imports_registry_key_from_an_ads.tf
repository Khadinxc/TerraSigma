resource "azurerm_sentinel_alert_rule_scheduled" "imports_registry_key_from_an_ads" {
  name                       = "imports_registry_key_from_an_ads"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Imports Registry Key From an ADS"
  description                = "Detects the import of a alternate datastream to the registry with regedit.exe."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((ProcessCommandLine contains " /i " or ProcessCommandLine contains ".reg") and ProcessCommandLine matches regex ":[^ \\\\]") and (FolderPath endswith "\\regedit.exe" or ProcessVersionInfoOriginalFileName =~ "REGEDIT.EXE")) and (not((ProcessCommandLine contains " -e " or ProcessCommandLine contains " /e " or ProcessCommandLine contains " –e " or ProcessCommandLine contains " —e " or ProcessCommandLine contains " ―e " or ProcessCommandLine contains " -a " or ProcessCommandLine contains " /a " or ProcessCommandLine contains " –a " or ProcessCommandLine contains " —a " or ProcessCommandLine contains " ―a " or ProcessCommandLine contains " -c " or ProcessCommandLine contains " /c " or ProcessCommandLine contains " –c " or ProcessCommandLine contains " —c " or ProcessCommandLine contains " ―c ")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1112"]
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