resource "azurerm_sentinel_alert_rule_scheduled" "potential_suspicious_change_to_sensitive_critical_files" {
  name                       = "potential_suspicious_change_to_sensitive_critical_files"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Suspicious Change To Sensitive/Critical Files"
  description                = "Detects changes of sensitive and critical files. Monitors files that you don't expect to change without planning on Linux system. - Some false positives are to be expected on user or administrator machines. Apply additional filters as needed."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains ">" and (FolderPath endswith "/cat" or FolderPath endswith "/echo" or FolderPath endswith "/grep" or FolderPath endswith "/head" or FolderPath endswith "/more" or FolderPath endswith "/tail")) or (FolderPath endswith "/emacs" or FolderPath endswith "/nano" or FolderPath endswith "/sed" or FolderPath endswith "/vi" or FolderPath endswith "/vim")) and (ProcessCommandLine contains "/bin/login" or ProcessCommandLine contains "/bin/passwd" or ProcessCommandLine contains "/boot/" or (ProcessCommandLine contains "/etc/" and ProcessCommandLine contains ".conf") or ProcessCommandLine contains "/etc/cron." or ProcessCommandLine contains "/etc/crontab" or ProcessCommandLine contains "/etc/hosts" or ProcessCommandLine contains "/etc/init.d" or ProcessCommandLine contains "/etc/sudoers" or ProcessCommandLine contains "/opt/bin/" or ProcessCommandLine contains "/sbin" or ProcessCommandLine contains "/usr/bin/" or ProcessCommandLine contains "/usr/local/bin/")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1565"]
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