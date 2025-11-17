resource "azurerm_sentinel_alert_rule_scheduled" "dotnet_assembly_dll_loaded_via_office_application" {
  name                       = "dotnet_assembly_dll_loaded_via_office_application"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "DotNET Assembly DLL Loaded Via Office Application"
  description                = "Detects any assembly DLL being loaded by an Office Product"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath startswith "C:\\Windows\\assembly\\" and (InitiatingProcessFolderPath endswith "\\excel.exe" or InitiatingProcessFolderPath endswith "\\mspub.exe" or InitiatingProcessFolderPath endswith "\\onenote.exe" or InitiatingProcessFolderPath endswith "\\onenoteim.exe" or InitiatingProcessFolderPath endswith "\\outlook.exe" or InitiatingProcessFolderPath endswith "\\powerpnt.exe" or InitiatingProcessFolderPath endswith "\\winword.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1204"]
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