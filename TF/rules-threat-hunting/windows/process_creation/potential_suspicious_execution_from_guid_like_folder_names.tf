resource "azurerm_sentinel_alert_rule_scheduled" "potential_suspicious_execution_from_guid_like_folder_names" {
  name                       = "potential_suspicious_execution_from_guid_like_folder_names"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Suspicious Execution From GUID Like Folder Names"
  description                = "Detects potential suspicious execution of a GUID like folder name located in a suspicious location such as %TEMP% as seen being used in IcedID attacks. Use this rule to hunt for potentially suspicious activity stemming from uncommon folders. - Installers are sometimes known for creating temporary folders with GUID like names. Add appropriate filters accordingly"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "\\AppData\\Roaming\\" or ProcessCommandLine contains "\\AppData\\Local\\Temp\\") and (ProcessCommandLine contains "\\{" and ProcessCommandLine contains "}\\")) and (not((FolderPath =~ "C:\\Windows\\System32\\drvinst.exe" or (FolderPath contains "\\{" and FolderPath contains "}\\") or (FolderPath in~ ("C:\\Windows\\System32\\msiexec.exe", "C:\\Windows\\SysWOW64\\msiexec.exe")) or isnull(FolderPath))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1027"]
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