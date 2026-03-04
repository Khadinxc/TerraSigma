resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_susp_child_process_as_system" {
  name                       = "proc_creation_win_susp_child_process_as_system"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Child Process Created as System"
  description                = "Detection of child processes spawned with SYSTEM privileges by parents with LOCAL SERVICE or NETWORK SERVICE accounts Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_child_process_as_system_.yml | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_child_process_as_system_.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessIntegrityLevel in~ ("System", "S-1-16-16384")) and (InitiatingProcessAccountName contains "AUTHORI" or InitiatingProcessAccountName contains "AUTORI") and ((InitiatingProcessAccountName =~ "NETWORK SERVICE" and InitiatingProcessAccountDomain startswith "") or (InitiatingProcessAccountName =~ "LOCAL SERVICE" and InitiatingProcessAccountDomain startswith "")) and (AccountName contains "AUTHORI" or AccountName contains "AUTORI") and ((AccountName =~ "SYSTEM" and AccountDomain startswith "") or (AccountName =~ "Système" and AccountDomain startswith "") or (AccountName =~ "СИСТЕМА" and AccountDomain startswith ""))) and (not((ProcessCommandLine contains "DavSetCookie" and FolderPath endswith "\\rundll32.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1134"]
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