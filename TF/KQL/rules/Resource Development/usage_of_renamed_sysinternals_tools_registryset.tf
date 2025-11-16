resource "azurerm_sentinel_alert_rule_scheduled" "usage_of_renamed_sysinternals_tools_registryset" {
  name                       = "usage_of_renamed_sysinternals_tools_registryset"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Usage of Renamed Sysinternals Tools - RegistrySet"
  description                = "Detects non-sysinternals tools setting the \"accepteula\" key which normally is set on sysinternals tool execution - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where ((RegistryKey contains "\\PsExec" or RegistryKey contains "\\ProcDump" or RegistryKey contains "\\Handle" or RegistryKey contains "\\LiveKd" or RegistryKey contains "\\Process Explorer" or RegistryKey contains "\\PsLoglist" or RegistryKey contains "\\PsPasswd" or RegistryKey contains "\\Active Directory Explorer") and RegistryKey endswith "\\EulaAccepted") and (not((InitiatingProcessFolderPath endswith "\\PsExec.exe" or InitiatingProcessFolderPath endswith "\\PsExec64.exe" or InitiatingProcessFolderPath endswith "\\procdump.exe" or InitiatingProcessFolderPath endswith "\\procdump64.exe" or InitiatingProcessFolderPath endswith "\\handle.exe" or InitiatingProcessFolderPath endswith "\\handle64.exe" or InitiatingProcessFolderPath endswith "\\livekd.exe" or InitiatingProcessFolderPath endswith "\\livekd64.exe" or InitiatingProcessFolderPath endswith "\\procexp.exe" or InitiatingProcessFolderPath endswith "\\procexp64.exe" or InitiatingProcessFolderPath endswith "\\psloglist.exe" or InitiatingProcessFolderPath endswith "\\psloglist64.exe" or InitiatingProcessFolderPath endswith "\\pspasswd.exe" or InitiatingProcessFolderPath endswith "\\pspasswd64.exe" or InitiatingProcessFolderPath endswith "\\ADExplorer.exe" or InitiatingProcessFolderPath endswith "\\ADExplorer64.exe"))) and (not(isnull(InitiatingProcessFolderPath)))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["ResourceDevelopment"]
  techniques                 = ["T1588"]
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
  }
}