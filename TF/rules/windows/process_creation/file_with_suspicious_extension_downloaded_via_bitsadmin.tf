resource "azurerm_sentinel_alert_rule_scheduled" "file_with_suspicious_extension_downloaded_via_bitsadmin" {
  name                       = "file_with_suspicious_extension_downloaded_via_bitsadmin"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File With Suspicious Extension Downloaded Via Bitsadmin"
  description                = "Detects usage of bitsadmin downloading a file with a suspicious extension"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ".7z" or ProcessCommandLine contains ".asax" or ProcessCommandLine contains ".ashx" or ProcessCommandLine contains ".asmx" or ProcessCommandLine contains ".asp" or ProcessCommandLine contains ".aspx" or ProcessCommandLine contains ".bat" or ProcessCommandLine contains ".cfm" or ProcessCommandLine contains ".cgi" or ProcessCommandLine contains ".chm" or ProcessCommandLine contains ".cmd" or ProcessCommandLine contains ".dll" or ProcessCommandLine contains ".gif" or ProcessCommandLine contains ".jpeg" or ProcessCommandLine contains ".jpg" or ProcessCommandLine contains ".jsp" or ProcessCommandLine contains ".jspx" or ProcessCommandLine contains ".log" or ProcessCommandLine contains ".png" or ProcessCommandLine contains ".ps1" or ProcessCommandLine contains ".psm1" or ProcessCommandLine contains ".rar" or ProcessCommandLine contains ".scf" or ProcessCommandLine contains ".sct" or ProcessCommandLine contains ".txt" or ProcessCommandLine contains ".vbe" or ProcessCommandLine contains ".vbs" or ProcessCommandLine contains ".war" or ProcessCommandLine contains ".wsf" or ProcessCommandLine contains ".wsh" or ProcessCommandLine contains ".xll" or ProcessCommandLine contains ".zip") and (ProcessCommandLine contains " /transfer " or ProcessCommandLine contains " /create " or ProcessCommandLine contains " /addfile ") and (FolderPath endswith "\\bitsadmin.exe" or ProcessVersionInfoOriginalFileName =~ "bitsadmin.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence"]
  techniques                 = ["T1197", "T1036"]
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
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}