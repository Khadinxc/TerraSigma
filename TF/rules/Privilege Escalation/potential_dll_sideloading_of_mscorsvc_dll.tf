resource "azurerm_sentinel_alert_rule_scheduled" "potential_dll_sideloading_of_mscorsvc_dll" {
  name                       = "potential_dll_sideloading_of_mscorsvc_dll"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential DLL Sideloading Of MsCorSvc.DLL"
  description                = "Detects potential DLL sideloading of \"mscorsvc.dll\". - Legitimate applications loading their own versions of the DLL mentioned in this rule."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath endswith "\\mscorsvc.dll" and (not((FolderPath startswith "C:\\Windows\\Microsoft.NET\\Framework\\" or FolderPath startswith "C:\\Windows\\Microsoft.NET\\Framework64\\" or FolderPath startswith "C:\\Windows\\Microsoft.NET\\FrameworkArm\\" or FolderPath startswith "C:\\Windows\\Microsoft.NET\\FrameworkArm64\\" or FolderPath startswith "C:\\Windows\\WinSxS\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "DefenseEvasion"]
  techniques                 = ["T1574"]
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}