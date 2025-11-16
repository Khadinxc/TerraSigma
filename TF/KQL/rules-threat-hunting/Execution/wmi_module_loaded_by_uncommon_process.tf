resource "azurerm_sentinel_alert_rule_scheduled" "wmi_module_loaded_by_uncommon_process" {
  name                       = "wmi_module_loaded_by_uncommon_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "WMI Module Loaded By Uncommon Process"
  description                = "Detects WMI modules being loaded by an uncommon process"
  severity                   = "Low"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath endswith "\\fastprox.dll" or FolderPath endswith "\\wbemcomn.dll" or FolderPath endswith "\\wbemprox.dll" or FolderPath endswith "\\wbemsvc.dll" or FolderPath endswith "\\WmiApRpl.dll" or FolderPath endswith "\\wmiclnt.dll" or FolderPath endswith "\\WMINet_Utils.dll" or FolderPath endswith "\\wmiprov.dll" or FolderPath endswith "\\wmiutils.dll") and (not((InitiatingProcessFolderPath contains ":\\Program Files (x86)\\" or InitiatingProcessFolderPath contains ":\\Program Files\\" or InitiatingProcessFolderPath contains ":\\Windows\\explorer.exe" or InitiatingProcessFolderPath contains ":\\Windows\\Microsoft.NET\\Framework\\" or InitiatingProcessFolderPath contains ":\\Windows\\Microsoft.NET\\FrameworkArm\\" or InitiatingProcessFolderPath contains ":\\Windows\\Microsoft.NET\\FrameworkArm64\\" or InitiatingProcessFolderPath contains ":\\Windows\\Microsoft.NET\\Framework64\\" or InitiatingProcessFolderPath contains ":\\Windows\\System32\\" or InitiatingProcessFolderPath contains ":\\Windows\\SysWOW64\\"))) and (not((InitiatingProcessFolderPath endswith "\\MsMpEng.exe" or (InitiatingProcessFolderPath endswith "\\WindowsAzureGuestAgent.exe" or InitiatingProcessFolderPath endswith "\\WaAppAgent.exe") or (InitiatingProcessFolderPath endswith ":\\Windows\\Sysmon.exe" or InitiatingProcessFolderPath endswith ":\\Windows\\Sysmon64.exe") or (InitiatingProcessFolderPath contains "\\Microsoft\\Teams\\current\\Teams.exe" or InitiatingProcessFolderPath contains "\\Microsoft\\Teams\\Update.exe") or (InitiatingProcessFolderPath endswith "\\thor.exe" or InitiatingProcessFolderPath endswith "\\thor64.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1047"]
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