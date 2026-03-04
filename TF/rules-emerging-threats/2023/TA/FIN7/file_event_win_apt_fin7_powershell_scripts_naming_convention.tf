resource "azurerm_sentinel_alert_rule_scheduled" "file_event_win_apt_fin7_powershell_scripts_naming_convention" {
  name                       = "file_event_win_apt_fin7_powershell_scripts_naming_convention"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential APT FIN7 Related PowerShell Script Created"
  description                = "Detects PowerShell script file creation with specific name or suffix which was seen being used often by FIN7 PowerShell scripts Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2023/TA/FIN7/file_event_win_apt_fin7_powershell_scripts_naming_convention.yml | Source: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2023/TA/FIN7/file_event_win_apt_fin7_powershell_scripts_naming_convention.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath in~ ("host_ip.ps1") or FolderPath endswith "_64refl.ps1"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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