resource "azurerm_sentinel_alert_rule_scheduled" "potential_file_extension_spoofing_using_right_to_left_override" {
  name                       = "potential_file_extension_spoofing_using_right_to_left_override"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential File Extension Spoofing Using Right-to-Left Override"
  description                = "Detects suspicious filenames that contain a right-to-left override character and a potentially spoofed file extensions. - Filenames that contains scriptures such as arabic or hebrew might make use of this character"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath contains "3pm." or FolderPath contains "4pm." or FolderPath contains "cod." or FolderPath contains "fdp." or FolderPath contains "ftr." or FolderPath contains "gepj." or FolderPath contains "gnp." or FolderPath contains "gpj." or FolderPath contains "ism." or FolderPath contains "lmth." or FolderPath contains "nls." or FolderPath contains "piz." or FolderPath contains "slx." or FolderPath contains "tdo." or FolderPath contains "vsc." or FolderPath contains "vwm." or FolderPath contains "xcod." or FolderPath contains "xslx." or FolderPath contains "xtpp.") and (FolderPath contains "\\u202e" or FolderPath contains "[U+202E]")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
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