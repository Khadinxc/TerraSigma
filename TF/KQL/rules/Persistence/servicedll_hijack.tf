resource "azurerm_sentinel_alert_rule_scheduled" "servicedll_hijack" {
  name                       = "servicedll_hijack"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "ServiceDll Hijack"
  description                = "Detects changes to the \"ServiceDLL\" value related to a service in the registry. This is often used as a method of persistence. - Administrative scripts - Installation of a service"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where ((RegistryKey endswith "\\System*" and RegistryKey contains "ControlSet" and RegistryKey endswith "\\Services*") and RegistryKey endswith "\\Parameters\\ServiceDll") and (not(((RegistryValueData =~ "%%systemroot%%\\system32\\ntdsa.dll" and InitiatingProcessFolderPath =~ "C:\\Windows\\system32\\lsass.exe" and RegistryKey endswith "\\Services\\NTDS\\Parameters\\ServiceDll") or InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\poqexec.exe" or RegistryValueData =~ "C:\\Windows\\system32\\spool\\drivers\\x64\\3\\PrintConfig.dll"))) and (not((RegistryValueData =~ "C:\\Windows\\System32\\STAgent.dll" and InitiatingProcessFolderPath endswith "\\regsvr32.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1543"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "InitiatingProcessFolderPath"
    }
  }

  entity_mapping {
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}