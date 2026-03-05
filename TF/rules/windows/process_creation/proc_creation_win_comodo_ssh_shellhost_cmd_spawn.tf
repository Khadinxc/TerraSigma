resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_comodo_ssh_shellhost_cmd_spawn" {
  name                       = "proc_creation_win_comodo_ssh_shellhost_cmd_spawn"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "OpenEDR Spawning Command Shell"
  description                = <<DESC
    Detects the OpenEDR ssh-shellhost.exe spawning a command shell (cmd.exe) or PowerShell with PTY (pseudo-terminal) capabilities. This may indicate remote command execution through OpenEDR's remote management features, which could be legitimate administrative activity or potential abuse of the remote access tool. Threat actors may leverage OpenEDR's remote shell capabilities to execute commands on compromised systems, facilitating lateral movement or other command-and-control operations.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_comodo_ssh_shellhost_cmd_spawn.yml

    False Positives:
    - Legitimate use of OpenEDR for remote command execution
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "bash" or ProcessCommandLine contains "cmd" or ProcessCommandLine contains "powershell" or ProcessCommandLine contains "pwsh") and (ProcessCommandLine contains "--pty" and FolderPath endswith "\\ssh-shellhost.exe" and InitiatingProcessFolderPath endswith "\\ITSMService.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "LateralMovement", "CommandAndControl"]
  techniques                 = ["T1059", "T1021", "T1219"]
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
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessAccountName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "InitiatingProcessAccountDomain"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "InitiatingProcessAccountSid"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "DeviceName"
    }
    field_mapping {
      identifier  = "AzureID"
      column_name = "DeviceId"
    }
  }

  entity_mapping {
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
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