resource "azurerm_sentinel_alert_rule_scheduled" "registry_set_office_trusted_location" {
  name                       = "registry_set_office_trusted_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Microsoft Office Trusted Location Updated"
  description                = <<DESC
    Detects changes to the registry keys related to "Trusted Location" of Microsoft Office. Attackers might add additional trusted locations to avoid macro security restrictions.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-threat-hunting/windows/registry/registry_set/registry_set_office_trusted_location.yml

    False Positives:
    - During office installations or setup, trusted locations are added, which will trigger this rule.
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey contains "Security\\Trusted Locations\\Location" and RegistryKey endswith "\\Path") and (not(((InitiatingProcessFolderPath contains ":\\Program Files\\Microsoft Office\\" or InitiatingProcessFolderPath contains ":\\Program Files (x86)\\Microsoft Office\\") or (InitiatingProcessFolderPath contains ":\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\" and InitiatingProcessFolderPath endswith "\\OfficeClickToRun.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence"]
  techniques                 = ["T1112"]
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