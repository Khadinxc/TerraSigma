resource "azurerm_sentinel_alert_rule_scheduled" "registry_event_runonce_persistence" {
  name                       = "registry_event_runonce_persistence"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Run Once Task Configuration in Registry"
  description                = <<DESC
    Rule to detect the configuration of Run Once registry key. Configured payload can be run by runonce.exe /AlternateShellStartup

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_event/registry_event_runonce_persistence.yml

    False Positives:
    - Legitimate modification of the registry key by legitimate program
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey contains "\\Microsoft\\Active Setup\\Installed Components" and RegistryKey endswith "\\StubPath") and (not(((RegistryValueData contains "C:\\Program Files\\Google\\Chrome\\Application\\" and RegistryValueData contains "\\Installer\\chrmstp.exe\" --configure-user-settings --verbose-logging --system-level") or ((RegistryValueData contains "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\" or RegistryValueData contains "C:\\Program Files\\Microsoft\\Edge\\Application\\") and RegistryValueData endswith "\\Installer\\setup.exe\" --configure-user-settings --verbose-logging --system-level --msedge --channel=stable"))))
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

  entity_mapping {
    entity_type = "RegistryValue"
    field_mapping {
      identifier  = "Value"
      column_name = "RegistryValueData"
    }
  }
}