resource "azurerm_sentinel_alert_rule_scheduled" "registry_set_dbgmanageddebugger_persistence" {
  name                       = "registry_set_dbgmanageddebugger_persistence"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Registry Persistence Attempt Via DbgManagedDebugger"
  description                = <<DESC
    Detects the addition of the "Debugger" value to the "DbgManagedDebugger" key in order to achieve persistence. Which will get invoked when an application crashes

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_dbgmanageddebugger_persistence.yml

    False Positives:
    - Legitimate use of the key to setup a debugger. Which is often the case on developers machines
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\Microsoft\\.NETFramework\\DbgManagedDebugger" and (not(RegistryValueData =~ "\"C:\\Windows\\system32\\vsjitdebugger.exe\" PID %d APPDOM %d EXTEXT \"%s\" EVTHDL %d"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion", "Persistence"]
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