resource "azurerm_sentinel_alert_rule_scheduled" "dll_names_used_by_svr_for_graphicalproton_backdoor" {
  name                       = "dll_names_used_by_svr_for_graphicalproton_backdoor"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "DLL Names Used By SVR For GraphicalProton Backdoor"
  description                = "Hunts known SVR-specific DLL names."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath endswith "\\AclNumsInvertHost.dll" or FolderPath endswith "\\AddressResourcesSpec.dll" or FolderPath endswith "\\BlendMonitorStringBuild.dll" or FolderPath endswith "\\ChildPaletteConnected.dll" or FolderPath endswith "\\DeregisterSeekUsers.dll" or FolderPath endswith "\\HandleFrequencyAll.dll" or FolderPath endswith "\\HardSwapColor.dll" or FolderPath endswith "\\LengthInMemoryActivate.dll" or FolderPath endswith "\\ModeBitmapNumericAnimate.dll" or FolderPath endswith "\\ModeFolderSignMove.dll" or FolderPath endswith "\\ParametersNamesPopup.dll" or FolderPath endswith "\\PerformanceCaptionApi.dll" or FolderPath endswith "\\ScrollbarHandleGet.dll" or FolderPath endswith "\\UnregisterAncestorAppendAuto.dll" or FolderPath endswith "\\WowIcmpRemoveReg.dll"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence", "PrivilegeEscalation"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}