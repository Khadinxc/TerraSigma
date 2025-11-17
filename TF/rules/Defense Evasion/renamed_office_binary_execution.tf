resource "azurerm_sentinel_alert_rule_scheduled" "renamed_office_binary_execution" {
  name                       = "renamed_office_binary_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Renamed Office Binary Execution"
  description                = "Detects the execution of a renamed office binary"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessVersionInfoOriginalFileName in~ ("Excel.exe", "MSACCESS.EXE", "MSPUB.EXE", "OneNote.exe", "OneNoteM.exe", "OUTLOOK.EXE", "POWERPNT.EXE", "WinWord.exe")) or (ProcessVersionInfoFileDescription in~ ("Microsoft Access", "Microsoft Excel", "Microsoft OneNote", "Microsoft Outlook", "Microsoft PowerPoint", "Microsoft Publisher", "Microsoft Word", "Sent to OneNote Tool"))) and (not((FolderPath endswith "\\EXCEL.exe" or FolderPath endswith "\\excelcnv.exe" or FolderPath endswith "\\MSACCESS.exe" or FolderPath endswith "\\MSPUB.EXE" or FolderPath endswith "\\ONENOTE.EXE" or FolderPath endswith "\\ONENOTEM.EXE" or FolderPath endswith "\\OUTLOOK.EXE" or FolderPath endswith "\\POWERPNT.EXE" or FolderPath endswith "\\WINWORD.exe")))
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