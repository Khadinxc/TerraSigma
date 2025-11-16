resource "azurerm_sentinel_alert_rule_scheduled" "potential_register_app_vbs_lolscript_abuse" {
  name                       = "potential_register_app_vbs_lolscript_abuse"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Register_App.Vbs LOLScript Abuse"
  description                = "Detects potential abuse of the \"register_app.vbs\" script that is part of the Windows SDK. The script offers the capability to register new VSS/VDS Provider as a COM+ application. Attackers can use this to install malicious DLLs for persistence and execution. - Other VB scripts that leverage the same starting command line flags"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains ".vbs -register " and ((FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\wscript.exe") or (ProcessVersionInfoOriginalFileName in~ ("cscript.exe", "wscript.exe")))
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