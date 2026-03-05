resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_dfsvc_suspicious_child_processes" {
  name                       = "proc_creation_win_dfsvc_suspicious_child_processes"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Child Process Of ClickOnce Application"
  description                = <<DESC
    Detects potentially suspicious child processes of a ClickOnce deployment application

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_dfsvc_suspicious_child_processes.yml
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\calc.exe" or FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\explorer.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\net.exe" or FolderPath endswith "\\net1.exe" or FolderPath endswith "\\nltest.exe" or FolderPath endswith "\\notepad.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\reg.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\schtasks.exe" or FolderPath endswith "\\werfault.exe" or FolderPath endswith "\\wscript.exe") and InitiatingProcessFolderPath contains "\\AppData\\Local\\Apps\\2.0\\"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
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