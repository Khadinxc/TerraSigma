resource "azurerm_sentinel_alert_rule_scheduled" "triple_cross_ebpf_rootkit_install_commands" {
  name                       = "triple_cross_ebpf_rootkit_install_commands"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Triple Cross eBPF Rootkit Install Commands"
  description                = "Detects default install commands of the Triple Cross eBPF rootkit based on the \"deployer.sh\" script - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " qdisc " or ProcessCommandLine contains " filter ") and (ProcessCommandLine contains " tc " and ProcessCommandLine contains " enp0s3 ") and FolderPath endswith "/sudo"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1014"]
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