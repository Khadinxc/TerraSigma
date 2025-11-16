resource "azurerm_sentinel_alert_rule_scheduled" "potential_suspicious_browser_launch_from_document_reader_process" {
  name                       = "potential_suspicious_browser_launch_from_document_reader_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Suspicious Browser Launch From Document Reader Process"
  description                = "Detects when a browser process or browser tab is launched from an application that handles document files such as Adobe, Microsoft Office, etc. And connects to a web application over http(s), this could indicate a possible phishing attempt. - Unlikely in most cases, further investigation should be done in the commandline of the browser process to determine the context of the URL accessed."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "http" and (FolderPath endswith "\\brave.exe" or FolderPath endswith "\\chrome.exe" or FolderPath endswith "\\firefox.exe" or FolderPath endswith "\\msedge.exe" or FolderPath endswith "\\opera.exe" or FolderPath endswith "\\maxthon.exe" or FolderPath endswith "\\seamonkey.exe" or FolderPath endswith "\\vivaldi.exe") and (InitiatingProcessFolderPath contains "Acrobat Reader" or InitiatingProcessFolderPath contains "Microsoft Office" or InitiatingProcessFolderPath contains "PDF Reader")) and (not(ProcessCommandLine contains "https://go.microsoft.com/fwlink/")) and (not(((ProcessCommandLine contains "http://ad.foxitsoftware.com/adlog.php") or (ProcessCommandLine contains "https://globe-map.foxitservice.com/go.php" and ProcessCommandLine contains "do=redirect"))))
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