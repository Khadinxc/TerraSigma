resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_sysinternals_procdump" {
  name                       = "proc_creation_win_sysinternals_procdump"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Procdump Execution"
  description                = "Detects usage of the SysInternals Procdump utility Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sysinternals_procdump.yml - Legitimate use of procdump by a developer or administrator | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sysinternals_procdump.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\procdump.exe" or FolderPath endswith "\\procdump64.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CredentialAccess"]
  techniques                 = ["T1036", "T1003"]
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