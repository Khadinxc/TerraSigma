resource "azurerm_sentinel_alert_rule_scheduled" "clipboard_data_collection_via_pbpaste" {
  name                       = "clipboard_data_collection_via_pbpaste"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Clipboard Data Collection Via Pbpaste"
  description                = "Detects execution of the \"pbpaste\" utility, which retrieves the contents of the clipboard (a.k.a. pasteboard) and writes them to the standard output (stdout). The utility is often used for creating new files with the clipboard content or for piping clipboard contents to other commands. It can also be used in shell scripts that may require clipboard content as input. Attackers can abuse this utility in order to collect data from the user clipboard, which may contain passwords or sensitive information. Use this rule to hunt for potential abuse of the utility by looking at the parent process and any potentially suspicious command line content. - Legitimate administration activities"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "/pbpaste"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection", "CredentialAccess"]
  techniques                 = ["T1115"]
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