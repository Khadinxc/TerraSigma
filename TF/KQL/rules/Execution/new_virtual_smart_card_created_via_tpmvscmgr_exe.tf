resource "azurerm_sentinel_alert_rule_scheduled" "new_virtual_smart_card_created_via_tpmvscmgr_exe" {
  name                       = "new_virtual_smart_card_created_via_tpmvscmgr_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New Virtual Smart Card Created Via TpmVscMgr.EXE"
  description                = "Detects execution of \"Tpmvscmgr.exe\" to create a new virtual smart card. - Legitimate usage by an administrator"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "create" and (FolderPath endswith "\\tpmvscmgr.exe" and ProcessVersionInfoOriginalFileName =~ "TpmVscMgr.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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