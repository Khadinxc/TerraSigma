resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_file_created_via_onenote_application" {
  name                       = "suspicious_file_created_via_onenote_application"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious File Created Via OneNote Application"
  description                = "Detects suspicious files created via the OneNote application. This could indicate a potential malicious \".one\"/\".onepkg\" file was executed as seen being used in malware activity in the wild - Occasional FPs might occur if OneNote is used internally to share different embedded documents"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath endswith "\\onenote.exe" or InitiatingProcessFolderPath endswith "\\onenotem.exe" or InitiatingProcessFolderPath endswith "\\onenoteim.exe") and FolderPath contains "\\AppData\\Local\\Temp\\OneNote\\" and (FolderPath endswith ".bat" or FolderPath endswith ".chm" or FolderPath endswith ".cmd" or FolderPath endswith ".dll" or FolderPath endswith ".exe" or FolderPath endswith ".hta" or FolderPath endswith ".htm" or FolderPath endswith ".html" or FolderPath endswith ".js" or FolderPath endswith ".lnk" or FolderPath endswith ".ps1" or FolderPath endswith ".vbe" or FolderPath endswith ".vbs" or FolderPath endswith ".wsf")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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