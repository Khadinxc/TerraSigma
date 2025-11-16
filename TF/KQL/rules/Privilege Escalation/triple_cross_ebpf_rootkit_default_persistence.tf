resource "azurerm_sentinel_alert_rule_scheduled" "triple_cross_ebpf_rootkit_default_persistence" {
  name                       = "triple_cross_ebpf_rootkit_default_persistence"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Triple Cross eBPF Rootkit Default Persistence"
  description                = "Detects the creation of \"ebpfbackdoor\" files in both \"cron.d\" and \"sudoers.d\" directories. Which both are related to the TripleCross persistence method - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith "ebpfbackdoor"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Execution", "Persistence", "DefenseEvasion"]
  techniques                 = ["T1053"]
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