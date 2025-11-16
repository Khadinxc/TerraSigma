resource "azurerm_sentinel_alert_rule_scheduled" "bypass_uac_using_silentcleanup_task" {
  name                       = "bypass_uac_using_silentcleanup_task"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Bypass UAC Using SilentCleanup Task"
  description                = "Detects the setting of the environement variable \"windir\" to a non default value. Attackers often abuse this variable in order to trigger a UAC bypass via the \"SilentCleanup\" task. The SilentCleanup task located in %windir%\\system32\\cleanmgr.exe is an auto-elevated task that can be abused to elevate any file with administrator privileges without prompting UAC."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\Environment\\windir" and (not(RegistryValueData =~ "%SystemRoot%"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion"]
  techniques                 = ["T1548"]
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
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}