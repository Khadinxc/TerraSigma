resource "azurerm_sentinel_alert_rule_scheduled" "potential_base64_decoded_from_images" {
  name                       = "potential_base64_decoded_from_images"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Base64 Decoded From Images"
  description                = "Detects the use of tail to extract bytes at an offset from an image and then decode the base64 value to create a new file with the decoded content. The detected execution is a bash one-liner."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "base64" and ProcessCommandLine contains "-d" and ProcessCommandLine contains ">") and (ProcessCommandLine contains ".avif" or ProcessCommandLine contains ".gif" or ProcessCommandLine contains ".jfif" or ProcessCommandLine contains ".jpeg" or ProcessCommandLine contains ".jpg" or ProcessCommandLine contains ".pjp" or ProcessCommandLine contains ".pjpeg" or ProcessCommandLine contains ".png" or ProcessCommandLine contains ".svg" or ProcessCommandLine contains ".webp") and FolderPath endswith "/bash" and (ProcessCommandLine contains "tail" and ProcessCommandLine contains "-c")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1140"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
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