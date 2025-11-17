resource "azurerm_sentinel_alert_rule_scheduled" "windows_spooler_service_suspicious_binary_load" {
  name                       = "windows_spooler_service_suspicious_binary_load"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Windows Spooler Service Suspicious Binary Load"
  description                = "Detect DLL Load from Spooler Service backup folder. This behavior has been observed during the exploitation of the Print Spooler Vulnerability CVE-2021-1675 and CVE-2021-34527 (PrinterNightmare). - Loading of legitimate driver"
  severity                   = "Informational"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath contains "\\Windows\\System32\\spool\\drivers\\x64\\3\\" or FolderPath contains "\\Windows\\System32\\spool\\drivers\\x64\\4\\") and FolderPath endswith ".dll" and InitiatingProcessFolderPath endswith "\\spoolsv.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion", "PrivilegeEscalation"]
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