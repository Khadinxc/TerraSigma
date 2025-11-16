resource "azurerm_sentinel_alert_rule_scheduled" "syslog_clearing_or_removal_via_system_utilities" {
  name                       = "syslog_clearing_or_removal_via_system_utilities"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Syslog Clearing or Removal Via System Utilities"
  description                = "Detects specific commands commonly used to remove or empty the syslog. Which is a technique often used by attacker as a method to hide their tracks - Log rotation. - Maintenance."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "/var/log/syslog" and ((ProcessCommandLine contains "/dev/null" and FolderPath endswith "/cp") or ((ProcessCommandLine contains "-sf " or ProcessCommandLine contains "-sfn " or ProcessCommandLine contains "-sfT ") and (ProcessCommandLine contains "/dev/null " and ProcessCommandLine contains "/var/log/syslog") and FolderPath endswith "/ln") or FolderPath endswith "/mv" or ((ProcessCommandLine contains " -r " or ProcessCommandLine contains " -f " or ProcessCommandLine contains " -rf " or ProcessCommandLine contains "/var/log/syslog") and FolderPath endswith "/rm") or (ProcessCommandLine contains "-u " and FolderPath endswith "/shred") or ((ProcessCommandLine contains "-s " or ProcessCommandLine contains "-c " or ProcessCommandLine contains "--size") and (ProcessCommandLine contains "0 " and ProcessCommandLine contains "/var/log/syslog") and FolderPath endswith "/truncate") or FolderPath endswith "/unlink")) or ((ProcessCommandLine contains "journalctl --vacuum" or ProcessCommandLine contains "journalctl --rotate") or (ProcessCommandLine contains " > /var/log/syslog" or ProcessCommandLine contains " >/var/log/syslog" or ProcessCommandLine contains " >| /var/log/syslog" or ProcessCommandLine contains ": > /var/log/syslog" or ProcessCommandLine contains ":> /var/log/syslog" or ProcessCommandLine contains ":>/var/log/syslog" or ProcessCommandLine contains ">|/var/log/syslog"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1070"]
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