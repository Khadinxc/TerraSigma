resource "azurerm_sentinel_alert_rule_scheduled" "uac_bypass_abusing_winsat_path_parsing_file" {
  name                       = "uac_bypass_abusing_winsat_path_parsing_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "UAC Bypass Abusing Winsat Path Parsing - File"
  description                = "Detects the pattern of UAC Bypass using a path parsing issue in winsat.exe (UACMe 52)"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath endswith "\\AppData\\Local\\Temp\\system32\\winsat.exe" or FolderPath endswith "\\AppData\\Local\\Temp\\system32\\winmm.dll") and FolderPath startswith "C:\\Users\\"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1548"]
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