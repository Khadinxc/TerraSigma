resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_installer_package_child_process" {
  name                       = "suspicious_installer_package_child_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Installer Package Child Process"
  description                = "Detects the execution of suspicious child processes from macOS installer package parent process. This includes osascript, JXA, curl and wget amongst other interpreters - Legitimate software uses the scripts (preinstall, postinstall)"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "preinstall" or ProcessCommandLine contains "postinstall") and (FolderPath endswith "/sh" or FolderPath endswith "/bash" or FolderPath endswith "/dash" or FolderPath endswith "/python" or FolderPath endswith "/ruby" or FolderPath endswith "/perl" or FolderPath endswith "/php" or FolderPath endswith "/javascript" or FolderPath endswith "/osascript" or FolderPath endswith "/tclsh" or FolderPath endswith "/curl" or FolderPath endswith "/wget") and (InitiatingProcessFolderPath endswith "/package_script_service" or InitiatingProcessFolderPath endswith "/installer")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "CommandAndControl"]
  techniques                 = ["T1059", "T1071"]
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