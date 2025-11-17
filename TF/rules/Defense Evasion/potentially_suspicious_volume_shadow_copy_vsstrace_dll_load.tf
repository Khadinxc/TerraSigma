resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_volume_shadow_copy_vsstrace_dll_load" {
  name                       = "potentially_suspicious_volume_shadow_copy_vsstrace_dll_load"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Volume Shadow Copy Vsstrace.dll Load"
  description                = "Detects the image load of VSS DLL by uncommon executables"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath endswith "\\vsstrace.dll" and (not((isnull(InitiatingProcessFolderPath) or (InitiatingProcessFolderPath startswith "C:\\Program Files\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\") or ((InitiatingProcessFolderPath in~ ("C:\\Windows\\explorer.exe", "C:\\Windows\\ImmersiveControlPanel\\SystemSettings.exe")) or (InitiatingProcessFolderPath startswith "C:\\Windows\\System32\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\SysWOW64\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\Temp\\{" or InitiatingProcessFolderPath startswith "C:\\Windows\\WinSxS\\" or InitiatingProcessFolderPath startswith "C:\\ProgramData\\Package Cache\\{"))))) and (not((InitiatingProcessFolderPath contains "\\temp\\is-" and InitiatingProcessFolderPath contains "\\avira_system_speedup.tmp")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Impact"]
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
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}