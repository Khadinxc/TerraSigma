resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_remote_access_tools_meshagent_exec" {
  name                       = "proc_creation_win_remote_access_tools_meshagent_exec"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Remote Access Tool - MeshAgent Command Execution via MeshCentral"
  description                = <<DESC
    Detects the use of MeshAgent to execute commands on the target host, particularly when threat actors might abuse it to execute commands directly. MeshAgent can execute commands on the target host by leveraging win-console to obscure their activities and win-dispatcher to run malicious code through IPC with child processes.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_remote_access_tools_meshagent_exec.yml

    False Positives:
    - False positives can be found in environments using MeshAgent for remote management, analysis should prioritize the grandparent process, MeshAgent.exe, and scrutinize the resulting child processes triggered by any suspicious interactive commands directed at the target host.
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") and InitiatingProcessFolderPath endswith "\\meshagent.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1219"]
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
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}