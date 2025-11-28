resource "azurerm_sentinel_alert_rule_scheduled" "potential_rjvplatform_dll_sideloading_from_non_default_location" {
  name                       = "potential_rjvplatform_dll_sideloading_from_non_default_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential RjvPlatform.DLL Sideloading From Non-Default Location"
  description                = "Detects potential DLL sideloading of \"RjvPlatform.dll\" by \"SystemResetPlatform.exe\" located in a non-default location. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (InitiatingProcessFolderPath =~ "\\SystemResetPlatform.exe" and FolderPath endswith "\\RjvPlatform.dll") and (not(InitiatingProcessFolderPath startswith "C:\\Windows\\System32\\SystemResetPlatform\\"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion", "PrivilegeEscalation"]
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