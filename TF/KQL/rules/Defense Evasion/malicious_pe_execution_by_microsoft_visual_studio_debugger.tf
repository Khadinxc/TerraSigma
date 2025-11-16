resource "azurerm_sentinel_alert_rule_scheduled" "malicious_pe_execution_by_microsoft_visual_studio_debugger" {
  name                       = "malicious_pe_execution_by_microsoft_visual_studio_debugger"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Malicious PE Execution by Microsoft Visual Studio Debugger"
  description                = "There is an option for a MS VS Just-In-Time Debugger \"vsjitdebugger.exe\" to launch specified executable and attach a debugger. This option may be used adversaries to execute malicious code by signed verified binary. The debugger is installed alongside with Microsoft Visual Studio package. - The process spawned by vsjitdebugger.exe is uncommon."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\vsjitdebugger.exe" and (not(((FolderPath contains "\\vsimmersiveactivatehelper" and FolderPath contains ".exe") or FolderPath endswith "\\devenv.exe")))
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