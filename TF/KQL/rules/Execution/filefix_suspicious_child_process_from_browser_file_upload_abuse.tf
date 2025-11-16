resource "azurerm_sentinel_alert_rule_scheduled" "filefix_suspicious_child_process_from_browser_file_upload_abuse" {
  name                       = "filefix_suspicious_child_process_from_browser_file_upload_abuse"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "FileFix - Suspicious Child Process from Browser File Upload Abuse"
  description                = "Detects potentially suspicious subprocesses such as LOLBINs spawned by web browsers. This activity could be associated with the \"FileFix\" social engineering technique, where users are tricked into launching the file explorer via a browser-based phishing page and pasting malicious commands into the address bar. The technique abuses clipboard manipulation and disguises command execution as benign file path access, resulting in covert execution of system utilities. - Legitimate use of PowerShell or other utilities launched from browser extensions or automation tools"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "#" and (FolderPath endswith "\\bitsadmin.exe" or FolderPath endswith "\\certutil.exe" or FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\regsvr32.exe") and (InitiatingProcessFolderPath endswith "\\brave.exe" or InitiatingProcessFolderPath endswith "\\chrome.exe" or InitiatingProcessFolderPath endswith "\\firefox.exe" or InitiatingProcessFolderPath endswith "\\msedge.exe")
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