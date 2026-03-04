resource "azurerm_sentinel_alert_rule_scheduled" "file_event_win_regedit_print_as_pdf" {
  name                       = "file_event_win_regedit_print_as_pdf"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PDF File Created By RegEdit.EXE"
  description                = "Detects the creation of a file with the \".pdf\" extension by the \"RegEdit.exe\" process. This indicates that a user is trying to print/save a registry key as a PDF in order to potentially extract sensitive information and bypass defenses. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_regedit_print_as_pdf.yml - Unlikely | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_regedit_print_as_pdf.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where InitiatingProcessFolderPath endswith "\\regedit.exe" and FolderPath endswith ".pdf"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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