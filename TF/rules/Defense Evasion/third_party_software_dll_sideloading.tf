resource "azurerm_sentinel_alert_rule_scheduled" "third_party_software_dll_sideloading" {
  name                       = "third_party_software_dll_sideloading"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Third Party Software DLL Sideloading"
  description                = "Detects DLL sideloading of DLLs that are part of third party software (zoom, discord....etc)"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath endswith "\\commfunc.dll" and (not((FolderPath contains "\\AppData\\local\\Google\\Chrome\\Application\\" or (FolderPath startswith "C:\\Program Files\\Lenovo\\Communications Utility\\" or FolderPath startswith "C:\\Program Files (x86)\\Lenovo\\Communications Utility\\"))))) or (FolderPath endswith "\\tosbtkbd.dll" and (not((FolderPath startswith "C:\\Program Files\\Toshiba\\Bluetooth Toshiba Stack\\" or FolderPath startswith "C:\\Program Files (x86)\\Toshiba\\Bluetooth Toshiba Stack\\"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence", "PrivilegeEscalation"]
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