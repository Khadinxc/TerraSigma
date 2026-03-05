resource "azurerm_sentinel_alert_rule_scheduled" "registry_event_disable_wdigest_credential_guard" {
  name                       = "registry_event_disable_wdigest_credential_guard"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Wdigest CredGuard Registry Modification"
  description                = <<DESC
    Detects potential malicious modification of the property value of IsCredGuardEnabled from HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest to disable Cred Guard on a system. This is usually used with UseLogonCredential to manipulate the caching credentials.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_event/registry_event_disable_wdigest_credential_guard.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\IsCredGuardEnabled"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
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