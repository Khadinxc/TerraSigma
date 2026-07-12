resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_node_new_agent_skills_installed" {
  name                       = "proc_creation_win_node_new_agent_skills_installed"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New Agent Skills Installation Attempt Via Node.EXE"
  description                = <<DESC
    Detects the attempt to install new skills for AI agents using the "npx skills" command. Agent skills enhance AI agents with new capabilities, but attackers may abuse this mechanism to inject malicious commands executed by the agent on behalf of the user. The "npx skills" command can install skills for various agents (e.g., Claude Code, Cursor, and others). Analysts should review any installed skills to verify their legitimacy. Note: Tune this rule based on whether AI agent tooling is allowed in your environment. In environments where such tooling is authorized, this detection may reflect normal activity and the alert level should be adjusted accordingly. In environments where AI agent tooling is not permitted, this activity is likely suspicious and may require immediate investigation.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_node_new_agent_skills_installed.yml

    False Positives:
    - This rule will be triggered when a new agent skill is installed regardless if it is benign or malicious.
    - High false positive rate expected in environments where AI agent tooling is authorized and commonly used.
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "npx-cli.js" and ProcessCommandLine contains "skills " and ProcessCommandLine contains " add ") and (FolderPath endswith "\\node.exe" or ProcessVersionInfoOriginalFileName =~ "node.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}