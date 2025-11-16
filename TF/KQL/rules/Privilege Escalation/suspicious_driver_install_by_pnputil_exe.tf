resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_driver_install_by_pnputil_exe" {
  name                       = "suspicious_driver_install_by_pnputil_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Driver Install by pnputil.exe"
  description                = "Detects when a possible suspicious driver is being installed via pnputil.exe lolbin - Pnputil.exe being used may be performed by a system administrator. - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. - Pnputil.exe being executed from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-i" or ProcessCommandLine contains "/install" or ProcessCommandLine contains "-a" or ProcessCommandLine contains "/add-driver" or ProcessCommandLine contains ".inf") and FolderPath endswith "\\pnputil.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1547"]
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