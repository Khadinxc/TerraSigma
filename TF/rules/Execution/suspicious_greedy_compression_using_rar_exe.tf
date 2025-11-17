resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_greedy_compression_using_rar_exe" {
  name                       = "suspicious_greedy_compression_using_rar_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Greedy Compression Using Rar.EXE"
  description                = "Detects RAR usage that creates an archive from a suspicious folder, either a system folder or one of the folders often used by attackers for staging purposes"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\rar.exe" or ProcessVersionInfoFileDescription =~ "Command line RAR") or (ProcessCommandLine contains ".exe a " or ProcessCommandLine contains " a -m")) and ((ProcessCommandLine contains " -hp" and ProcessCommandLine contains " -r ") and ((ProcessCommandLine contains " " and ProcessCommandLine contains ":*.") or (ProcessCommandLine contains " " and ProcessCommandLine contains ":\*.") or (ProcessCommandLine contains " " and ProcessCommandLine contains ":\\$Recycle.bin\\") or (ProcessCommandLine contains " " and ProcessCommandLine contains ":\\PerfLogs\\") or (ProcessCommandLine contains " " and ProcessCommandLine contains ":\\Temp") or (ProcessCommandLine contains " " and ProcessCommandLine contains ":\\Users\\Public\\") or (ProcessCommandLine contains " " and ProcessCommandLine contains ":\\Windows\\") or ProcessCommandLine contains " %public%"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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