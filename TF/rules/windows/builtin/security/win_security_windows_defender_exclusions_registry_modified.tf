resource "azurerm_sentinel_alert_rule_scheduled" "win_security_windows_defender_exclusions_registry_modified" {
  name                       = "win_security_windows_defender_exclusions_registry_modified"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Windows Defender Exclusion List Modified"
  description                = <<DESC
    Detects modifications to the Windows Defender exclusion registry key. This could indicate a potentially suspicious or even malicious activity by an attacker trying to add a new exclusion in order to bypass security.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_windows_defender_exclusions_registry_modified.yml

    False Positives:
    - Intended exclusions by administrators
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\Microsoft\\Windows Defender\\Exclusions*"
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
    entity_type = "RegistryKey"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }
}