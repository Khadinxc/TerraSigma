resource "azurerm_sentinel_alert_rule_scheduled" "winrar_compressing_dump_files" {
  name                       = "winrar_compressing_dump_files"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Winrar Compressing Dump Files"
  description                = "Detects execution of WinRAR in order to compress a file with a \".dmp\"/\".dump\" extension, which could be a step in a process of dump file exfiltration. - Legitimate use of WinRAR with a command line in which \".dmp\" or \".dump\" appears accidentally - Legitimate use of WinRAR to compress WER \".dmp\" files for troubleshooting"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ".dmp" or ProcessCommandLine contains ".dump" or ProcessCommandLine contains ".hdmp") and ((FolderPath endswith "\\rar.exe" or FolderPath endswith "\\winrar.exe") or ProcessVersionInfoFileDescription =~ "Command line RAR")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection"]
  techniques                 = ["T1560"]
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