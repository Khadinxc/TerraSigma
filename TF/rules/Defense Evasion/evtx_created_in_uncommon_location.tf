resource "azurerm_sentinel_alert_rule_scheduled" "evtx_created_in_uncommon_location" {
  name                       = "evtx_created_in_uncommon_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "EVTX Created In Uncommon Location"
  description                = "Detects the creation of new files with the \".evtx\" extension in non-common or non-standard location. This could indicate tampering with default EVTX locations in order to evade security controls or simply exfiltration of event log to search for sensitive information within. Note that backup software and legitimate administrator might perform similar actions during troubleshooting. - Administrator or backup activity - An unknown bug seems to trigger the Windows \"svchost\" process to drop EVTX files in the \"C:\\Windows\\Temp\" directory in the form \"<log_name\">_<uuid>.evtx\". See https://superuser.com/questions/1371229/low-disk-space-after-filling-up-c-windows-temp-with-evtx-and-txt-files"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith ".evtx" and (not(((FolderPath endswith "\\Windows\\System32\\winevt\\Logs\\" and FolderPath startswith "C:\\ProgramData\\Microsoft\\Windows\\Containers\\BaseImages\\") or FolderPath startswith "C:\\Windows\\System32\\winevt\\Logs\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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