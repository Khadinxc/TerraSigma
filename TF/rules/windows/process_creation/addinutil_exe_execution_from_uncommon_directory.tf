resource "azurerm_sentinel_alert_rule_scheduled" "addinutil_exe_execution_from_uncommon_directory" {
  name                       = "addinutil_exe_execution_from_uncommon_directory"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "AddinUtil.EXE Execution From Uncommon Directory"
  description                = "Detects execution of the Add-In deployment cache updating utility (AddInutil.exe) from a non-standard directory."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\addinutil.exe" or ProcessVersionInfoOriginalFileName =~ "AddInUtil.exe") and (not((FolderPath contains ":\\Windows\\Microsoft.NET\\Framework\\" or FolderPath contains ":\\Windows\\Microsoft.NET\\Framework64\\" or FolderPath contains ":\\Windows\\Microsoft.NET\\FrameworkArm\\" or FolderPath contains ":\\Windows\\Microsoft.NET\\FrameworkArm64\\" or FolderPath contains ":\\Windows\\WinSxS\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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