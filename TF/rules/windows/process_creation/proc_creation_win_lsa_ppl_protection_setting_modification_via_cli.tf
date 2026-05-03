resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_lsa_ppl_protection_setting_modification_via_cli" {
  name                       = "proc_creation_win_lsa_ppl_protection_setting_modification_via_cli"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "LSA PPL Protection Setting Modification via CommandLine"
  description                = <<DESC
    Detects modification of LSA PPL protection settings via CommandLine. It may indicate an attempt to disable protection and enable credential dumping tools to access LSASS process memory.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_lsa_ppl_protection_setting_modification_via_cli.yml

    False Positives:
    - Unlikely
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "Set-ItemProperty" or ProcessCommandLine contains "New-ItemProperty" or ProcessCommandLine contains " add ") and (ProcessCommandLine contains "ControlSet" and ProcessCommandLine contains "\\Control\\Lsa")) and ((FolderPath endswith "\\reg.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("reg.exe", "powershell.exe", "pwsh.dll"))) and (ProcessCommandLine contains "IsPplAutoEnabled" or ProcessCommandLine contains "RunAsPPL" or ProcessCommandLine contains "RunAsPPLBoot")
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
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}