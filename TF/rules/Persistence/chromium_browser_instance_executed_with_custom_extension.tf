resource "azurerm_sentinel_alert_rule_scheduled" "chromium_browser_instance_executed_with_custom_extension" {
  name                       = "chromium_browser_instance_executed_with_custom_extension"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Chromium Browser Instance Executed With Custom Extension"
  description                = "Detects a Chromium based browser process with the 'load-extension' flag to start a instance with a custom extension - Usage of Chrome Extensions in testing tools such as BurpSuite will trigger this alert"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "--load-extension=" and (FolderPath endswith "\\brave.exe" or FolderPath endswith "\\chrome.exe" or FolderPath endswith "\\msedge.exe" or FolderPath endswith "\\opera.exe" or FolderPath endswith "\\vivaldi.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
  techniques                 = ["T1176"]
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