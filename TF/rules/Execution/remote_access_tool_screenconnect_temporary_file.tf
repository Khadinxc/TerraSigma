resource "azurerm_sentinel_alert_rule_scheduled" "remote_access_tool_screenconnect_temporary_file" {
  name                       = "remote_access_tool_screenconnect_temporary_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Remote Access Tool - ScreenConnect Temporary File"
  description                = "Detects the creation of files in a specific location by ScreenConnect RMM. ScreenConnect has feature to remotely execute binaries on a target machine. These binaries will be dropped to \":\\Users\\<username>\\Documents\\ConnectWiseControl\\Temp\\\" before execution. - Legitimate use of ScreenConnect"
  severity                   = "Low"
  query                      = <<QUERY
DeviceFileEvents
| where InitiatingProcessFolderPath endswith "\\ScreenConnect.WindowsClient.exe" and FolderPath contains "\\Documents\\ConnectWiseControl\\Temp\\"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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