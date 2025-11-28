resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_word_cab_file_write_cve_2021_40444" {
  name                       = "suspicious_word_cab_file_write_cve_2021_40444"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Word Cab File Write CVE-2021-40444"
  description                = "Detects file creation patterns noticeable during the exploitation of CVE-2021-40444"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where ((InitiatingProcessFolderPath endswith "\\winword.exe" and FolderPath contains "\\Windows\\INetCache" and FolderPath endswith ".cab") or (InitiatingProcessFolderPath endswith "\\winword.exe" and (FolderPath contains "\\AppData\\Local\\Temp\\" and FolderPath contains ".inf"))) and (not((FolderPath contains "AppData\\Local\\Temp" and FolderPath endswith "\\Content.inf" and FolderPath startswith "C:\\Users\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["ResourceDevelopment"]
  techniques                 = ["T1587"]
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