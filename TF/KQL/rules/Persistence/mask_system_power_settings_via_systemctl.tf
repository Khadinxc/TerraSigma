resource "azurerm_sentinel_alert_rule_scheduled" "mask_system_power_settings_via_systemctl" {
  name                       = "mask_system_power_settings_via_systemctl"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Mask System Power Settings Via Systemctl"
  description                = "Detects the use of systemctl mask to disable system power management targets such as suspend, hibernate, or hybrid sleep. Adversaries may mask these targets to prevent a system from entering sleep or shutdown states, ensuring their malicious processes remain active and uninterrupted. This behavior can be associated with persistence or defense evasion, as it impairs normal system power operations to maintain long-term access or avoid termination of malicious activity. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "suspend.target" or ProcessCommandLine contains "hibernate.target" or ProcessCommandLine contains "hybrid-sleep.target") and (ProcessCommandLine contains " mask" and FolderPath endswith "/systemctl")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "Impact"]
  techniques                 = ["T1653"]
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