resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_lolbin_settingsynchost" {
  name                       = "proc_creation_win_lolbin_settingsynchost"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Using SettingSyncHost.exe as LOLBin"
  description                = "Detects using SettingSyncHost.exe to run hijacked binary Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_lolbin_settingsynchost.yml | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_lolbin_settingsynchost.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (not((FolderPath startswith "C:\\Windows\\System32\\" or FolderPath startswith "C:\\Windows\\SysWOW64\\"))) and (InitiatingProcessCommandLine contains "cmd.exe /c" and InitiatingProcessCommandLine contains "RoamDiag.cmd" and InitiatingProcessCommandLine contains "-outputpath")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "Execution", "DefenseEvasion"]
  techniques                 = ["T1574"]
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