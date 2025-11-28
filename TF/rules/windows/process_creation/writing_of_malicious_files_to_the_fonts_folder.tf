resource "azurerm_sentinel_alert_rule_scheduled" "writing_of_malicious_files_to_the_fonts_folder" {
  name                       = "writing_of_malicious_files_to_the_fonts_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Writing Of Malicious Files To The Fonts Folder"
  description                = "Monitors for the hiding possible malicious files in the C:\\Windows\\Fonts\\ location. This folder doesn't require admin privillege to be written and executed from."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "echo" or ProcessCommandLine contains "copy" or ProcessCommandLine contains "type" or ProcessCommandLine contains "file createnew" or ProcessCommandLine contains "cacls") and ProcessCommandLine contains "C:\\Windows\\Fonts\\" and (ProcessCommandLine contains ".sh" or ProcessCommandLine contains ".exe" or ProcessCommandLine contains ".dll" or ProcessCommandLine contains ".bin" or ProcessCommandLine contains ".bat" or ProcessCommandLine contains ".cmd" or ProcessCommandLine contains ".js" or ProcessCommandLine contains ".msh" or ProcessCommandLine contains ".reg" or ProcessCommandLine contains ".scr" or ProcessCommandLine contains ".ps" or ProcessCommandLine contains ".vb" or ProcessCommandLine contains ".jar" or ProcessCommandLine contains ".pl" or ProcessCommandLine contains ".inf" or ProcessCommandLine contains ".cpl" or ProcessCommandLine contains ".hta" or ProcessCommandLine contains ".msi" or ProcessCommandLine contains ".vbs")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence", "Execution"]
  techniques                 = ["T1211", "T1059"]
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
}