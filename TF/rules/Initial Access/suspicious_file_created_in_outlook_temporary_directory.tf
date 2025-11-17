resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_file_created_in_outlook_temporary_directory" {
  name                       = "suspicious_file_created_in_outlook_temporary_directory"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious File Created in Outlook Temporary Directory"
  description                = "Detects the creation of files with suspicious file extensions in the temporary directory that Outlook uses when opening attachments. This can be used to detect spear-phishing campaigns that use suspicious files as attachments, which may contain malicious code. - Opening of headers or footers in email signatures that include SVG images or legitimate SVG attachments"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath endswith ".cpl" or FolderPath endswith ".hta" or FolderPath endswith ".iso" or FolderPath endswith ".rdp" or FolderPath endswith ".svg" or FolderPath endswith ".vba" or FolderPath endswith ".vbe" or FolderPath endswith ".vbs") and ((FolderPath contains "\\AppData\\Local\\Packages\\Microsoft.Outlook_" or FolderPath contains "\\AppData\\Local\\Microsoft\\Olk\\Attachments\\") or (FolderPath contains "\\AppData\\Local\\Microsoft\\Windows\\" and FolderPath contains "\\Content.Outlook\\"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess"]
  techniques                 = ["T1566"]
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