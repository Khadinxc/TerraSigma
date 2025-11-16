resource "azurerm_sentinel_alert_rule_scheduled" "flush_iptables_ufw_chain" {
  name                       = "flush_iptables_ufw_chain"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Flush Iptables Ufw Chain"
  description                = "Detect use of iptables to flush all firewall rules, tables and chains and allow all network traffic - Network administrators"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "/iptables" or FolderPath endswith "/xtables-legacy-multi" or FolderPath endswith "/iptables-legacy-multi" or FolderPath endswith "/ip6tables" or FolderPath endswith "/ip6tables-legacy-multi") and (ProcessCommandLine contains "-F" or ProcessCommandLine contains "-Z" or ProcessCommandLine contains "-X") and (ProcessCommandLine contains "ufw-logging-deny" or ProcessCommandLine contains "ufw-logging-allow" or ProcessCommandLine contains "ufw6-logging-deny" or ProcessCommandLine contains "ufw6-logging-allow")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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