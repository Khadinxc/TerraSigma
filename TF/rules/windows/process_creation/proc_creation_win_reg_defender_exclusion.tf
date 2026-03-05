resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_reg_defender_exclusion" {
  name                       = "proc_creation_win_reg_defender_exclusion"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Windows Defender Folder Exclusion Added Via Reg.EXE"
  description                = <<DESC
    Detects the usage of "reg.exe" to add Defender folder exclusions. Qbot has been seen using this technique to add exclusions for folders within AppData and ProgramData.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_reg_defender_exclusion.yml

    False Positives:
    - Legitimate use
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths" or ProcessCommandLine contains "SOFTWARE\\Microsoft\\Microsoft Antimalware\\Exclusions\\Paths") and (ProcessCommandLine contains "ADD " and ProcessCommandLine contains "/t " and ProcessCommandLine contains "REG_DWORD " and ProcessCommandLine contains "/v " and ProcessCommandLine contains "/d " and ProcessCommandLine contains "0") and FolderPath endswith "\\reg.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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