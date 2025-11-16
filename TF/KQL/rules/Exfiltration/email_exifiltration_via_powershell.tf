resource "azurerm_sentinel_alert_rule_scheduled" "email_exifiltration_via_powershell" {
  name                       = "email_exifiltration_via_powershell"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Email Exifiltration Via Powershell"
  description                = "Detects email exfiltration via powershell cmdlets"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "Add-PSSnapin" and ProcessCommandLine contains "Get-Recipient" and ProcessCommandLine contains "-ExpandProperty" and ProcessCommandLine contains "EmailAddresses" and ProcessCommandLine contains "SmtpAddress" and ProcessCommandLine contains "-hidetableheaders") and (FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Exfiltration"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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