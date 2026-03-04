resource "azurerm_sentinel_alert_rule_scheduled" "image_load_office_vbadll_load" {
  name                       = "image_load_office_vbadll_load"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "VBA DLL Loaded Via Office Application"
  description                = "Detects VB DLL's loaded by an office application. Which could indicate the presence of VBA Macros. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/image_load_office_vbadll_load.yml - Legitimate macro usage. Add the appropriate filter according to your environment | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/image_load_office_vbadll_load.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath endswith "\\VBE7.DLL" or FolderPath endswith "\\VBEUI.DLL" or FolderPath endswith "\\VBE7INTL.DLL") and (InitiatingProcessFolderPath endswith "\\excel.exe" or InitiatingProcessFolderPath endswith "\\mspub.exe" or InitiatingProcessFolderPath endswith "\\onenote.exe" or InitiatingProcessFolderPath endswith "\\onenoteim.exe" or InitiatingProcessFolderPath endswith "\\outlook.exe" or InitiatingProcessFolderPath endswith "\\powerpnt.exe" or InitiatingProcessFolderPath endswith "\\winword.exe")
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