resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_file_write_to_sharepoint_layouts_directory" {
  name                       = "suspicious_file_write_to_sharepoint_layouts_directory"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious File Write to SharePoint Layouts Directory"
  description                = "Detects suspicious file writes to SharePoint layouts directory which could indicate webshell activity or post-exploitation. This behavior has been observed in the exploitation of SharePoint vulnerabilities such as CVE-2025-49704, CVE-2025-49706 or CVE-2025-53770."
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath endswith "\\cmd.exe" or InitiatingProcessFolderPath endswith "\\powershell_ise.exe" or InitiatingProcessFolderPath endswith "\\powershell.exe" or InitiatingProcessFolderPath endswith "\\pwsh.exe" or InitiatingProcessFolderPath endswith "\\w3wp.exe") and (FolderPath contains "\\15\\TEMPLATE\\LAYOUTS\\" or FolderPath contains "\\16\\TEMPLATE\\LAYOUTS\\") and (FolderPath endswith ".asax" or FolderPath endswith ".ascx" or FolderPath endswith ".ashx" or FolderPath endswith ".asmx" or FolderPath endswith ".asp" or FolderPath endswith ".aspx" or FolderPath endswith ".bat" or FolderPath endswith ".cmd" or FolderPath endswith ".cer" or FolderPath endswith ".config" or FolderPath endswith ".hta" or FolderPath endswith ".js" or FolderPath endswith ".jsp" or FolderPath endswith ".jspx" or FolderPath endswith ".php" or FolderPath endswith ".ps1" or FolderPath endswith ".vbs") and (FolderPath startswith "C:\\Program Files\\Common Files\\Microsoft Shared\\Web Server Extensions\\" or FolderPath startswith "C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\Web Server Extensions\\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess", "Persistence"]
  techniques                 = ["T1190", "T1505"]
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