resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_webdav_client_execution_via_rundll32_exe" {
  name                       = "suspicious_webdav_client_execution_via_rundll32_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious WebDav Client Execution Via Rundll32.EXE"
  description                = "Detects \"svchost.exe\" spawning \"rundll32.exe\" with command arguments like C:\\windows\\system32\\davclnt.dll,DavSetCookie. This could be an indicator of exfiltration or use of WebDav to launch code (hosted on WebDav Server) or potentially a sign of exploitation of CVE-2023-23397"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "C:\\windows\\system32\\davclnt.dll,DavSetCookie" and ProcessCommandLine matches regex "://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}" and FolderPath endswith "\\rundll32.exe" and InitiatingProcessCommandLine contains "-s WebClient" and InitiatingProcessFolderPath endswith "\\svchost.exe") and (not((ProcessCommandLine contains "://10." or ProcessCommandLine contains "://192.168." or ProcessCommandLine contains "://172.16." or ProcessCommandLine contains "://172.17." or ProcessCommandLine contains "://172.18." or ProcessCommandLine contains "://172.19." or ProcessCommandLine contains "://172.20." or ProcessCommandLine contains "://172.21." or ProcessCommandLine contains "://172.22." or ProcessCommandLine contains "://172.23." or ProcessCommandLine contains "://172.24." or ProcessCommandLine contains "://172.25." or ProcessCommandLine contains "://172.26." or ProcessCommandLine contains "://172.27." or ProcessCommandLine contains "://172.28." or ProcessCommandLine contains "://172.29." or ProcessCommandLine contains "://172.30." or ProcessCommandLine contains "://172.31." or ProcessCommandLine contains "://127." or ProcessCommandLine contains "://169.254.")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Exfiltration"]
  techniques                 = ["T1048"]
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