resource "azurerm_sentinel_alert_rule_scheduled" "file_delete_win_delete_exchange_powershell_logs" {
  name                       = "file_delete_win_delete_exchange_powershell_logs"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Exchange PowerShell Cmdlet History Deleted"
  description                = <<DESC
    Detects the deletion of the Exchange PowerShell cmdlet History logs which may indicate an attempt to destroy forensic evidence

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_delete/file_delete_win_delete_exchange_powershell_logs.yml

    False Positives:
    - Possible FP during log rotation
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath contains "_Cmdlet_" and FolderPath startswith "\\Logging\\CmdletInfra\\LocalPowerShell\\Cmdlet\\"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1070"]
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