resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_office_document_executed_from_trusted_location" {
  name                       = "potentially_suspicious_office_document_executed_from_trusted_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Office Document Executed From Trusted Location"
  description                = "Detects the execution of an Office application that points to a document that is located in a trusted location. Attackers often used this to avoid macro security and execute their malicious code."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((FolderPath endswith "\\EXCEL.EXE" or FolderPath endswith "\\POWERPNT.EXE" or FolderPath endswith "\\WINWORD.exe") or (ProcessVersionInfoOriginalFileName in~ ("Excel.exe", "POWERPNT.EXE", "WinWord.exe"))) and (InitiatingProcessFolderPath endswith "\\explorer.exe" or InitiatingProcessFolderPath endswith "\\dopus.exe") and (ProcessCommandLine contains "\\AppData\\Roaming\\Microsoft\\Templates" or ProcessCommandLine contains "\\AppData\\Roaming\\Microsoft\\Word\\Startup\\" or ProcessCommandLine contains "\\Microsoft Office\\root\\Templates\\" or ProcessCommandLine contains "\\Microsoft Office\\Templates\\")) and (not((ProcessCommandLine endswith ".dotx" or ProcessCommandLine endswith ".xltx" or ProcessCommandLine endswith ".potx")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1202"]
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