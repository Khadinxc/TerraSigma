resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_package_installed_linux" {
  name                       = "suspicious_package_installed_linux"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Package Installed - Linux"
  description                = "Detects installation of suspicious packages using system installation utilities - Legitimate administration activities"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "install" and (FolderPath endswith "/apt" or FolderPath endswith "/apt-get")) or ((ProcessCommandLine contains "--install" or ProcessCommandLine contains "-i") and FolderPath endswith "/dpkg") or (ProcessCommandLine contains "-i" and FolderPath endswith "/rpm") or ((ProcessCommandLine contains "localinstall" or ProcessCommandLine contains "install") and FolderPath endswith "/yum")) and (ProcessCommandLine contains "nmap" or ProcessCommandLine contains " nc" or ProcessCommandLine contains "netcat" or ProcessCommandLine contains "wireshark" or ProcessCommandLine contains "tshark" or ProcessCommandLine contains "openconnect" or ProcessCommandLine contains "proxychains")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1553"]
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