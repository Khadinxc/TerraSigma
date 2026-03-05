resource "azurerm_sentinel_alert_rule_scheduled" "registry_set_susp_printer_driver" {
  name                       = "registry_set_susp_printer_driver"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Printer Driver Empty Manufacturer"
  description                = <<DESC
    Detects a suspicious printer driver installation with an empty Manufacturer value

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_susp_printer_driver.yml

    False Positives:
    - Alerts on legitimate printer drivers that do not set any more details in the Manufacturer value
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData =~ "(Empty)" and (RegistryKey contains "\\Control\\Print\\Environments\\Windows x64\\Drivers" and RegistryKey contains "\\Manufacturer")) and (not((RegistryKey endswith "\\CutePDF Writer v4.0*" or RegistryKey endswith "\\Version-3\\PDF24*" or (RegistryKey endswith "\\VNC Printer (PS)*" or RegistryKey endswith "\\VNC Printer (UD)*"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1574"]
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