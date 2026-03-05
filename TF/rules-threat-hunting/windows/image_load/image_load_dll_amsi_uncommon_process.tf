resource "azurerm_sentinel_alert_rule_scheduled" "image_load_dll_amsi_uncommon_process" {
  name                       = "image_load_dll_amsi_uncommon_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Amsi.DLL Load By Uncommon Process"
  description                = <<DESC
    Detects loading of Amsi.dll by uncommon processes

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-threat-hunting/windows/image_load/image_load_dll_amsi_uncommon_process.yml

    False Positives:
    - Legitimate third party apps installed in "ProgramData" and "AppData" might generate some false positives. Apply additional filters accordingly
  DESC
  severity                   = "Low"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath endswith "\\amsi.dll" and (not((((InitiatingProcessFolderPath contains ":\\Windows\\Microsoft.NET\\Framework\\" or InitiatingProcessFolderPath contains ":\\Windows\\Microsoft.NET\\Framework64\\" or InitiatingProcessFolderPath contains ":\\Windows\\Microsoft.NET\\FrameworkArm\\" or InitiatingProcessFolderPath contains ":\\Windows\\Microsoft.NET\\FrameworkArm64\\") and InitiatingProcessFolderPath endswith "\\ngentask.exe") or InitiatingProcessFolderPath =~ "" or (InitiatingProcessFolderPath endswith ":\\Windows\\explorer.exe" or InitiatingProcessFolderPath endswith ":\\Windows\\Sysmon64.exe") or (InitiatingProcessFolderPath contains ":\\Program Files (x86)\\" or InitiatingProcessFolderPath contains ":\\Program Files\\" or InitiatingProcessFolderPath contains ":\\Windows\\System32\\" or InitiatingProcessFolderPath contains ":\\Windows\\SysWOW64\\" or InitiatingProcessFolderPath contains ":\\Windows\\WinSxS\\") or isnull(InitiatingProcessFolderPath)))) and (not((InitiatingProcessFolderPath contains ":\\ProgramData\\Microsoft\\Windows Defender\\Platform\\" and InitiatingProcessFolderPath endswith "\\MsMpEng.exe")))
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