resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_file_created_by_arcsoc_exe" {
  name                       = "suspicious_file_created_by_arcsoc_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious File Created by ArcSOC.exe"
  description                = "Detects instances where the ArcGIS Server process ArcSOC.exe, which hosts REST services running on an ArcGIS server, creates a file with suspicious file type, indicating that it may be an executable, script file, or otherwise unusual. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where InitiatingProcessFolderPath endswith "\\ArcSOC.exe" and (FolderPath endswith ".ahk" or FolderPath endswith ".aspx" or FolderPath endswith ".au3" or FolderPath endswith ".bat" or FolderPath endswith ".cmd" or FolderPath endswith ".dll" or FolderPath endswith ".exe" or FolderPath endswith ".hta" or FolderPath endswith ".js" or FolderPath endswith ".ps1" or FolderPath endswith ".py" or FolderPath endswith ".vbe" or FolderPath endswith ".vbs" or FolderPath endswith ".wsf")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CommandAndControl", "Persistence", "InitialAccess"]
  techniques                 = ["T1127", "T1105", "T1133"]
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