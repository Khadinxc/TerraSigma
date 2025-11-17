resource "azurerm_sentinel_alert_rule_scheduled" "baaupdate_exe_suspicious_dll_load" {
  name                       = "baaupdate_exe_suspicious_dll_load"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "BaaUpdate.exe Suspicious DLL Load"
  description                = "Detects BitLocker Access Agent Update Utility (baaupdate.exe) loading DLLs from suspicious locations that are publicly writable which could indicate an attempt to lateral movement via BitLocker DCOM & COM Hijacking. This technique abuses COM Classes configured as INTERACTIVE USER to spawn processes in the context of the logged-on user's session. Specifically, it targets the BDEUILauncher Class (CLSID ab93b6f1-be76-4185-a488-a9001b105b94) which can launch BaaUpdate.exe, which is vulnerable to COM Hijacking when started with input parameters. This allows attackers to execute code in the user's context without needing to steal credentials or use additional techniques to compromise the account."
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath contains ":\\Perflogs\\" or FolderPath contains ":\\Users\\Default\\" or FolderPath contains ":\\Users\\Public\\" or FolderPath contains ":\\Windows\\Temp\\" or FolderPath contains "\\AppData\\Local\\Temp\\" or FolderPath contains "\\AppData\\Roaming\\" or FolderPath contains "\\Contacts\\" or FolderPath contains "\\Favorites\\" or FolderPath contains "\\Favourites\\" or FolderPath contains "\\Links\\" or FolderPath contains "\\Music\\" or FolderPath contains "\\Pictures\\" or FolderPath contains "\\ProgramData\\" or FolderPath contains "\\Temporary Internet" or FolderPath contains "\\Videos\\") and FolderPath endswith ".dll" and InitiatingProcessFolderPath endswith "\\BaaUpdate.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "LateralMovement"]
  techniques                 = ["T1218", "T1021"]
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