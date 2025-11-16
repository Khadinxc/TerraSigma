resource "azurerm_sentinel_alert_rule_scheduled" "linux_sudo_chroot_execution" {
  name                       = "linux_sudo_chroot_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Linux Sudo Chroot Execution"
  description                = "Detects the execution of 'sudo' command with '--chroot' option, which is used to change the root directory for command execution. Attackers may use this technique to evade detection and execute commands in a modified environment. This can be part of a privilege escalation strategy, as it allows the execution of commands with elevated privileges in a controlled environment as seen in CVE-2025-32463. While investigating, look out for unusual or unexpected use of 'sudo --chroot' in conjunction with other commands or scripts such as execution from temporary directories or unusual user accounts. - Legitimate administrative tasks or scripts that use 'sudo --chroot' for containerization, testing, or system management."
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " --chroot " or ProcessCommandLine contains "sudo -R ") and FolderPath endswith "/sudo"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation"]
  techniques                 = ["T1068"]
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