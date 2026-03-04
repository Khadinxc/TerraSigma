resource "azurerm_sentinel_alert_rule_scheduled" "image_load_side_load_wazuh" {
  name                       = "image_load_side_load_wazuh"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Wazuh Security Platform DLL Sideloading"
  description                = "Detects potential DLL side loading of DLLs that are part of the Wazuh security platform Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/image_load_side_load_wazuh.yml - Many legitimate applications leverage this DLL. (Visual Studio, JetBrains, Ruby, Anaconda, GithubDesktop, etc.) | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/image_load_side_load_wazuh.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath endswith "\\libwazuhshared.dll" or FolderPath endswith "\\libwinpthread-1.dll") and (not((FolderPath startswith "C:\\Program Files\\" or FolderPath startswith "C:\\Program Files (x86)\\"))) and (not(((FolderPath contains "\\AppData\\Local\\" or FolderPath contains "\\ProgramData\\") and FolderPath endswith "\\mingw64\\bin\\libwinpthread-1.dll")))
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