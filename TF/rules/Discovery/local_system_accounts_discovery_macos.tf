resource "azurerm_sentinel_alert_rule_scheduled" "local_system_accounts_discovery_macos" {
  name                       = "local_system_accounts_discovery_macos"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Local System Accounts Discovery - MacOs"
  description                = "Detects enumeration of local systeam accounts on MacOS - Legitimate administration activities"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "list" and ProcessCommandLine contains "/users") and FolderPath endswith "/dscl") or ((ProcessCommandLine contains "-q" and ProcessCommandLine contains "user") and FolderPath endswith "/dscacheutil") or ProcessCommandLine contains "'x:0:'" or ((ProcessCommandLine contains "/etc/passwd" or ProcessCommandLine contains "/etc/sudoers") and FolderPath endswith "/cat") or FolderPath endswith "/id" or (ProcessCommandLine contains "-u" and FolderPath endswith "/lsof")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1087"]
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