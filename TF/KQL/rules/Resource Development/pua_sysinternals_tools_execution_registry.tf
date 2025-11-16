resource "azurerm_sentinel_alert_rule_scheduled" "pua_sysinternals_tools_execution_registry" {
  name                       = "pua_sysinternals_tools_execution_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - Sysinternals Tools Execution - Registry"
  description                = "Detects the execution of some potentially unwanted tools such as PsExec, Procdump, etc. (part of the Sysinternals suite) via the creation of the \"accepteula\" registry key. - Legitimate use of SysInternals tools. Filter the legitimate paths used in your environment"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where ActionType =~ "RegistryKeyCreated" and (RegistryKey contains "\\Active Directory Explorer" or RegistryKey contains "\\Handle" or RegistryKey contains "\\LiveKd" or RegistryKey contains "\\Process Explorer" or RegistryKey contains "\\ProcDump" or RegistryKey contains "\\PsExec" or RegistryKey contains "\\PsLoglist" or RegistryKey contains "\\PsPasswd" or RegistryKey contains "\\SDelete" or RegistryKey contains "\\Sysinternals") and RegistryKey endswith "\\EulaAccepted"
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
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }
}