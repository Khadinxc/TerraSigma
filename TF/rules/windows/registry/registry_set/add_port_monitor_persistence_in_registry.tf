resource "azurerm_sentinel_alert_rule_scheduled" "add_port_monitor_persistence_in_registry" {
  name                       = "add_port_monitor_persistence_in_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Add Port Monitor Persistence in Registry"
  description                = "Adversaries may use port monitors to run an attacker supplied DLL during system boot for persistence or privilege escalation. A port monitor can be set through the AddMonitor API call to set a DLL to be loaded at startup."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData endswith ".dll" and RegistryKey endswith "\\Control\\Print\\Monitors*") and (not(((RegistryValueData =~ "cpwmon64_v40.dll" and InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\spoolsv.exe" and RegistryKey contains "\\Control\\Print\\Monitors\\CutePDF Writer Monitor v4.0\\Driver" and (InitiatingProcessAccountName contains "AUTHORI" or InitiatingProcessAccountName contains "AUTORI")) or RegistryKey contains "\\Control\\Print\\Monitors\\MONVNC\\Driver" or (RegistryKey endswith "Control\\Print\\Environments*" and RegistryKey endswith "\\Drivers*" and RegistryKey contains "\\VNC Printer"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1547"]
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
    field_mapping {
      identifier  = "UPNSuffix"
      column_name = "InitiatingProcessAccountUpn"
    }
    field_mapping {
      identifier  = "AadUserId"
      column_name = "InitiatingProcessAccountObjectId"
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