resource "azurerm_sentinel_alert_rule_scheduled" "deletion_of_volume_shadow_copies_via_wmi_with_powershell" {
  name                       = "deletion_of_volume_shadow_copies_via_wmi_with_powershell"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Deletion of Volume Shadow Copies via WMI with PowerShell"
  description                = "Detects deletion of Windows Volume Shadow Copies with PowerShell code and Get-WMIObject. This technique is used by numerous ransomware families such as Sodinokibi/REvil"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ".Delete()" or ProcessCommandLine contains "Remove-WmiObject" or ProcessCommandLine contains "rwmi" or ProcessCommandLine contains "Remove-CimInstance" or ProcessCommandLine contains "rcim") and (ProcessCommandLine contains "Get-WmiObject" or ProcessCommandLine contains "gwmi" or ProcessCommandLine contains "Get-CimInstance" or ProcessCommandLine contains "gcim") and ProcessCommandLine contains "Win32_ShadowCopy"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1490"]
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
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }
}