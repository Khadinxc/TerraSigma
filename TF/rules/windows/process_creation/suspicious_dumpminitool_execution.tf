resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_dumpminitool_execution" {
  name                       = "suspicious_dumpminitool_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious DumpMinitool Execution"
  description                = "Detects suspicious ways to use the \"DumpMinitool.exe\" binary"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\DumpMinitool.exe" or FolderPath endswith "\\DumpMinitool.x86.exe" or FolderPath endswith "\\DumpMinitool.arm64.exe") or (ProcessVersionInfoOriginalFileName in~ ("DumpMinitool.exe", "DumpMinitool.x86.exe", "DumpMinitool.arm64.exe"))) and ((not((FolderPath contains "\\Microsoft Visual Studio\\" or FolderPath contains "\\Extensions\\"))) or ProcessCommandLine contains ".txt" or ((ProcessCommandLine contains " Full" or ProcessCommandLine contains " Mini" or ProcessCommandLine contains " WithHeap") and (not(ProcessCommandLine contains "--dumpType"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CredentialAccess"]
  techniques                 = ["T1036", "T1003"]
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
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}