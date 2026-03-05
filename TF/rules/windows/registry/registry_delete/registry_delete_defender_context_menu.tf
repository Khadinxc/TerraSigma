resource "azurerm_sentinel_alert_rule_scheduled" "registry_delete_defender_context_menu" {
  name                       = "registry_delete_defender_context_menu"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Delete Defender Scan ShellEx Context Menu Registry Key"
  description                = <<DESC
    Detects deletion of registry key that adds 'Scan with Defender' option in context menu. Attackers may use this to make it harder for users to scan files that are suspicious.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_delete/registry_delete_defender_context_menu.yml

    False Positives:
    - Unlikely as this weakens defenses and normally would not be done even if using another AV.
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "shellex\\ContextMenuHandlers\\EPP" and (not((InitiatingProcessFolderPath endswith "\\MsMpEng.exe" and (InitiatingProcessFolderPath startswith "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\Windows Defender\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Windows Defender\\"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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
    entity_type = "RegistryKey"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }
}