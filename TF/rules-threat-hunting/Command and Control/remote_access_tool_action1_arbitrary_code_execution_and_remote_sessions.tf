resource "azurerm_sentinel_alert_rule_scheduled" "remote_access_tool_action1_arbitrary_code_execution_and_remote_sessions" {
  name                       = "remote_access_tool_action1_arbitrary_code_execution_and_remote_sessions"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Remote Access Tool - Action1 Arbitrary Code Execution and Remote Sessions"
  description                = "Detects the execution of Action1 in order to execute arbitrary code or establish a remote session. Action1 is a powerful Remote Monitoring and Management tool that enables users to execute commands, scripts, and binaries. Through the web interface of action1, the administrator must create a new policy or an app to establish remote execution and then points that the agent is installed. Hunting Opportunity 1- Weed Out The Noise When threat actors execute a script, a command, or a binary through these new policies and apps, the names of these become visible in the command line during the execution process. Below is an example of the command line that contains the deployment of a binary through  a policy with name \"test_app_1\": ParentCommandLine: \"C:\\WINDOWS\\Action1\\action1_agent.exe schedule:Deploy_App__test_app_1_1681327673425 runaction:0\" After establishing a baseline, we can split the command to extract the policy name and group all the policy names and inspect the results with a list of frequency occurrences. Hunting Opportunity 2 - Remote Sessions On Out Of Office Hours If you have admins within your environment using remote sessions to administer endpoints, you can create a threat-hunting query and modify the time of the initiated sessions looking for abnormal activity. - If Action1 is among the approved software in your environment, you might find that this is a noisy query. See description for ideas on how to alter this query and start looking for suspicious activities."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath contains "\\Windows\\Action1\\package_downloads\\" and InitiatingProcessFolderPath endswith "\\action1_agent.exe") or ((InitiatingProcessCommandLine contains "\\Action1\\scripts\\Run_Command_" or InitiatingProcessCommandLine contains "\\Action1\\scripts\\Run_PowerShell_") and (InitiatingProcessFolderPath endswith "\\cmd.exe" or InitiatingProcessFolderPath endswith "\\powershell.exe")) or FolderPath endswith "\\agent1_remote.exe"
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
    field_mapping {
      identifier  = "UPNSuffix"
      column_name = "InitiatingProcessAccountUpn"
    }
    field_mapping {
      identifier  = "AadUserId"
      column_name = "InitiatingProcessAccountObjectId"
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