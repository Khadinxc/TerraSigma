resource "azurerm_sentinel_alert_rule_scheduled" "file_event_win_powershell_module_susp_creation" {
  name                       = "file_event_win_powershell_module_susp_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Suspicious PowerShell Module File Created"
  description                = <<DESC
    Detects the creation of a new PowerShell module in the first folder of the module directory structure "\WindowsPowerShell\Modules\malware\malware.psm1". This is somewhat an uncommon practice as legitimate modules often includes a version folder.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_powershell_module_susp_creation.yml

    False Positives:
    - False positive rate will vary depending on the environments. Additional filters might be required to make this logic usable in production.
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath contains "\\WindowsPowerShell\\Modules\\" and FolderPath contains "\\.ps") or (FolderPath contains "\\WindowsPowerShell\\Modules\\" and FolderPath contains "\\.dll")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
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