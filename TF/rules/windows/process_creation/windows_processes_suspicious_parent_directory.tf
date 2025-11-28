resource "azurerm_sentinel_alert_rule_scheduled" "windows_processes_suspicious_parent_directory" {
  name                       = "windows_processes_suspicious_parent_directory"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Windows Processes Suspicious Parent Directory"
  description                = "Detect suspicious parent processes of well-known Windows processes - Some security products seem to spawn these"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\svchost.exe" or FolderPath endswith "\\taskhost.exe" or FolderPath endswith "\\lsm.exe" or FolderPath endswith "\\lsass.exe" or FolderPath endswith "\\services.exe" or FolderPath endswith "\\lsaiso.exe" or FolderPath endswith "\\csrss.exe" or FolderPath endswith "\\wininit.exe" or FolderPath endswith "\\winlogon.exe") and (not((((InitiatingProcessFolderPath contains "\\Windows Defender\\" or InitiatingProcessFolderPath contains "\\Microsoft Security Client\\") and InitiatingProcessFolderPath endswith "\\MsMpEng.exe") or (isnull(InitiatingProcessFolderPath) or (InitiatingProcessFolderPath in~ ("", "-"))) or ((InitiatingProcessFolderPath endswith "\\SavService.exe" or InitiatingProcessFolderPath endswith "\\ngen.exe") or (InitiatingProcessFolderPath contains "\\System32\\" or InitiatingProcessFolderPath contains "\\SysWOW64\\")))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036"]
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