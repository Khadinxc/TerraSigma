resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_double_extension_file_execution" {
  name                       = "suspicious_double_extension_file_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Double Extension File Execution"
  description                = "Detects suspicious use of an .exe extension after a non-executable file extension like .pdf.exe, a set of spaces or underlines to cloak the executable file in spear phishing campaigns"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "      .exe" or ProcessCommandLine contains "______.exe" or ProcessCommandLine contains ".doc.exe" or ProcessCommandLine contains ".doc.js" or ProcessCommandLine contains ".docx.exe" or ProcessCommandLine contains ".docx.js" or ProcessCommandLine contains ".gif.exe" or ProcessCommandLine contains ".jpeg.exe" or ProcessCommandLine contains ".jpg.exe" or ProcessCommandLine contains ".mkv.exe" or ProcessCommandLine contains ".mov.exe" or ProcessCommandLine contains ".mp3.exe" or ProcessCommandLine contains ".mp4.exe" or ProcessCommandLine contains ".pdf.exe" or ProcessCommandLine contains ".pdf.js" or ProcessCommandLine contains ".png.exe" or ProcessCommandLine contains ".ppt.exe" or ProcessCommandLine contains ".ppt.js" or ProcessCommandLine contains ".pptx.exe" or ProcessCommandLine contains ".pptx.js" or ProcessCommandLine contains ".rtf.exe" or ProcessCommandLine contains ".rtf.js" or ProcessCommandLine contains ".svg.exe" or ProcessCommandLine contains ".txt.exe" or ProcessCommandLine contains ".txt.js" or ProcessCommandLine contains ".xls.exe" or ProcessCommandLine contains ".xls.js" or ProcessCommandLine contains ".xlsx.exe" or ProcessCommandLine contains ".xlsx.js" or ProcessCommandLine contains "⠀⠀⠀⠀⠀⠀.exe") and (FolderPath endswith "      .exe" or FolderPath endswith "______.exe" or FolderPath endswith ".doc.exe" or FolderPath endswith ".doc.js" or FolderPath endswith ".docx.exe" or FolderPath endswith ".docx.js" or FolderPath endswith ".gif.exe" or FolderPath endswith ".jpeg.exe" or FolderPath endswith ".jpg.exe" or FolderPath endswith ".mkv.exe" or FolderPath endswith ".mov.exe" or FolderPath endswith ".mp3.exe" or FolderPath endswith ".mp4.exe" or FolderPath endswith ".pdf.exe" or FolderPath endswith ".pdf.js" or FolderPath endswith ".png.exe" or FolderPath endswith ".ppt.exe" or FolderPath endswith ".ppt.js" or FolderPath endswith ".pptx.exe" or FolderPath endswith ".pptx.js" or FolderPath endswith ".rtf.exe" or FolderPath endswith ".rtf.js" or FolderPath endswith ".svg.exe" or FolderPath endswith ".txt.exe" or FolderPath endswith ".txt.js" or FolderPath endswith ".xls.exe" or FolderPath endswith ".xls.js" or FolderPath endswith ".xlsx.exe" or FolderPath endswith ".xlsx.js" or FolderPath endswith "⠀⠀⠀⠀⠀⠀.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess"]
  techniques                 = ["T1566"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
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