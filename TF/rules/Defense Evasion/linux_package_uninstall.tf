resource "azurerm_sentinel_alert_rule_scheduled" "linux_package_uninstall" {
  name                       = "linux_package_uninstall"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Linux Package Uninstall"
  description                = "Detects linux package removal using builtin tools such as \"yum\", \"apt\", \"apt-get\" or \"dpkg\". - Administrator or administrator scripts might delete packages for several reasons (debugging, troubleshooting)."
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "remove" or ProcessCommandLine contains "purge") and (FolderPath endswith "/apt" or FolderPath endswith "/apt-get")) or ((ProcessCommandLine contains "--remove " or ProcessCommandLine contains " -r ") and FolderPath endswith "/dpkg") or (ProcessCommandLine contains " -e " and FolderPath endswith "/rpm") or ((ProcessCommandLine contains "erase" or ProcessCommandLine contains "remove") and FolderPath endswith "/yum")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1070"]
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