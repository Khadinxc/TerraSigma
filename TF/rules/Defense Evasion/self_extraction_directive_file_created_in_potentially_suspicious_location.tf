resource "azurerm_sentinel_alert_rule_scheduled" "self_extraction_directive_file_created_in_potentially_suspicious_location" {
  name                       = "self_extraction_directive_file_created_in_potentially_suspicious_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Self Extraction Directive File Created In Potentially Suspicious Location"
  description                = "Detects the creation of Self Extraction Directive files (.sed) in a potentially suspicious location. These files are used by the \"iexpress.exe\" utility in order to create self extracting packages. Attackers were seen abusing this utility and creating PE files with embedded \".sed\" entries."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath contains ":\\ProgramData\\" or FolderPath contains ":\\Temp\\" or FolderPath contains ":\\Windows\\System32\\Tasks\\" or FolderPath contains ":\\Windows\\Tasks\\" or FolderPath contains ":\\Windows\\Temp\\" or FolderPath contains "\\AppData\\Local\\Temp\\") and FolderPath endswith ".sed"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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