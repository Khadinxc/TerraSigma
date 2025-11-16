resource "azurerm_sentinel_alert_rule_scheduled" "potential_plugx_activity" {
  name                       = "potential_plugx_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential PlugX Activity"
  description                = "Detects the execution of an executable that is typically used by PlugX for DLL side loading starting from an uncommon location"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\CamMute.exe" and (not((FolderPath contains "\\Lenovo\\Communication Utility\\" or FolderPath contains "\\Lenovo\\Communications Utility\\")))) or (FolderPath endswith "\\chrome_frame_helper.exe" and (not(FolderPath contains "\\Google\\Chrome\\application\\"))) or (FolderPath endswith "\\dvcemumanager.exe" and (not(FolderPath contains "\\Microsoft Device Emulator\\"))) or (FolderPath endswith "\\Gadget.exe" and (not(FolderPath contains "\\Windows Media Player\\"))) or (FolderPath endswith "\\hcc.exe" and (not(FolderPath contains "\\HTML Help Workshop\\"))) or (FolderPath endswith "\\hkcmd.exe" and (not((FolderPath contains "\\System32\\" or FolderPath contains "\\SysNative\\" or FolderPath contains "\\SysWow64\\")))) or (FolderPath endswith "\\Mc.exe" and (not((FolderPath contains "\\Microsoft Visual Studio" or FolderPath contains "\\Microsoft SDK" or FolderPath contains "\\Windows Kit")))) or (FolderPath endswith "\\MsMpEng.exe" and (not((FolderPath contains "\\Microsoft Security Client\\" or FolderPath contains "\\Windows Defender\\" or FolderPath contains "\\AntiMalware\\")))) or (FolderPath endswith "\\msseces.exe" and (not((FolderPath contains "\\Microsoft Security Center\\" or FolderPath contains "\\Microsoft Security Client\\" or FolderPath contains "\\Microsoft Security Essentials\\")))) or (FolderPath endswith "\\OInfoP11.exe" and (not(FolderPath contains "\\Common Files\\Microsoft Shared\\"))) or (FolderPath endswith "\\OleView.exe" and (not((FolderPath contains "\\Microsoft Visual Studio" or FolderPath contains "\\Microsoft SDK" or FolderPath contains "\\Windows Kit" or FolderPath contains "\\Windows Resource Kit\\")))) or (FolderPath endswith "\\rc.exe" and (not((FolderPath contains "\\Microsoft Visual Studio" or FolderPath contains "\\Microsoft SDK" or FolderPath contains "\\Windows Kit" or FolderPath contains "\\Windows Resource Kit\\" or FolderPath contains "\\Microsoft.NET\\"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "DefenseEvasion"]
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