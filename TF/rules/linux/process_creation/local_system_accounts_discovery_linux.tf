resource "azurerm_sentinel_alert_rule_scheduled" "local_system_accounts_discovery_linux" {
  name                       = "local_system_accounts_discovery_linux"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Local System Accounts Discovery - Linux"
  description                = "Detects enumeration of local systeam accounts. This information can help adversaries determine which local accounts exist on a system to aid in follow-on behavior. - Legitimate administration activities"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "/lastlog" or ProcessCommandLine contains "'x:0:'" or ((ProcessCommandLine contains "/etc/passwd" or ProcessCommandLine contains "/etc/shadow" or ProcessCommandLine contains "/etc/sudoers" or ProcessCommandLine contains "/etc/spwd.db" or ProcessCommandLine contains "/etc/pwd.db" or ProcessCommandLine contains "/etc/master.passwd") and (FolderPath endswith "/cat" or FolderPath endswith "/ed" or FolderPath endswith "/head" or FolderPath endswith "/more" or FolderPath endswith "/nano" or FolderPath endswith "/tail" or FolderPath endswith "/vi" or FolderPath endswith "/vim" or FolderPath endswith "/less" or FolderPath endswith "/emacs" or FolderPath endswith "/sqlite3" or FolderPath endswith "/makemap")) or FolderPath endswith "/id" or (ProcessCommandLine contains "-u" and FolderPath endswith "/lsof")
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