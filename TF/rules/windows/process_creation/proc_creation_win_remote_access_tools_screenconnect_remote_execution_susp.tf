resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_remote_access_tools_screenconnect_remote_execution_susp" {
  name                       = "proc_creation_win_remote_access_tools_screenconnect_remote_execution_susp"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Remote Access Tool - ScreenConnect Potential Suspicious Remote Command Execution"
  description                = <<DESC
    Detects potentially suspicious child processes launched via the ScreenConnect client service.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_remote_access_tools_screenconnect_remote_execution_susp.yml

    False Positives:
    - If the script being executed make use of any of the utilities mentioned in the detection then they should filtered out or allowed.
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\bitsadmin.exe" or FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\curl.exe" or FolderPath endswith "\\dllhost.exe" or FolderPath endswith "\\net.exe" or FolderPath endswith "\\nltest.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\wevtutil.exe") and (InitiatingProcessCommandLine contains ":\\Windows\\TEMP\\ScreenConnect\\" and InitiatingProcessCommandLine contains "run.cmd")
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