resource "azurerm_sentinel_alert_rule_scheduled" "visual_studio_code_tunnel_shell_execution" {
  name                       = "visual_studio_code_tunnel_shell_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Visual Studio Code Tunnel Shell Execution"
  description                = "Detects the execution of a shell (powershell, bash, wsl...) via Visual Studio Code tunnel. Attackers can abuse this functionality to establish a C2 channel and execute arbitrary commands on the system. - Legitimate use of Visual Studio Code tunnel and running code from there"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (InitiatingProcessCommandLine contains ".vscode-server" and InitiatingProcessFolderPath contains "\\servers\\Stable-" and InitiatingProcessFolderPath endswith "\\server\\node.exe") and ((ProcessCommandLine contains "\\terminal\\browser\\media\\shellIntegration.ps1" and (FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe")) or (FolderPath endswith "\\wsl.exe" or FolderPath endswith "\\bash.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1071"]
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