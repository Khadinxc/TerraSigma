resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_susp_sensitive_file_access_shadowcopy" {
  name                       = "proc_creation_win_susp_sensitive_file_access_shadowcopy"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Sensitive File Access Via Volume Shadow Copy Backup"
  description                = <<DESC
    Detects a command that accesses the VolumeShadowCopy in order to extract sensitive files such as the Security or SAM registry hives or the AD database (ntds.dit)

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_sensitive_file_access_shadowcopy.yml

    False Positives:
    - Unlikely
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" and (ProcessCommandLine contains "\\NTDS.dit" or ProcessCommandLine contains "\\SYSTEM" or ProcessCommandLine contains "\\SECURITY")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1490"]
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
}