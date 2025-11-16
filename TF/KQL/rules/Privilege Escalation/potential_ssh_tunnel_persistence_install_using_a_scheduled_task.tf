resource "azurerm_sentinel_alert_rule_scheduled" "potential_ssh_tunnel_persistence_install_using_a_scheduled_task" {
  name                       = "potential_ssh_tunnel_persistence_install_using_a_scheduled_task"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential SSH Tunnel Persistence Install Using A Scheduled Task"
  description                = "Detects the creation of new scheduled tasks via commandline, using Schtasks.exe. This rule detects tasks creating that call OpenSSH, which may indicate the creation of reverse SSH tunnel to the attacker's server."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\schtasks.exe" or ProcessVersionInfoOriginalFileName =~ "schtasks.exe") and ((ProcessCommandLine contains " /create " and ProcessCommandLine contains "ssh.exe" and ProcessCommandLine contains "-i") or (ProcessCommandLine contains " /create " and ProcessCommandLine contains "sshd.exe" and ProcessCommandLine contains "-f"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "Execution", "CommandAndControl"]
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
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
    field_mapping {
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}