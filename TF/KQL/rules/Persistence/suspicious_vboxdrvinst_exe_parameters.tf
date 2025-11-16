resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_vboxdrvinst_exe_parameters" {
  name                       = "suspicious_vboxdrvinst_exe_parameters"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious VBoxDrvInst.exe Parameters"
  description                = "Detect VBoxDrvInst.exe run with parameters allowing processing INF file. This allows to create values in the registry and install drivers. For example one could use this technique to obtain persistence via modifying one of Run or RunOnce registry keys - Legitimate use of VBoxDrvInst.exe utility by VirtualBox Guest Additions installation process"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "driver" and ProcessCommandLine contains "executeinf") and FolderPath endswith "\\VBoxDrvInst.exe"
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