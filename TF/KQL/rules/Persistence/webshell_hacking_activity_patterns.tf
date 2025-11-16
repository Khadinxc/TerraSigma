resource "azurerm_sentinel_alert_rule_scheduled" "webshell_hacking_activity_patterns" {
  name                       = "webshell_hacking_activity_patterns"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Webshell Hacking Activity Patterns"
  description                = "Detects certain parent child patterns found in cases in which a web shell is used to perform certain credential dumping or exfiltration activities on a compromised system - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((InitiatingProcessFolderPath contains "-tomcat-" or InitiatingProcessFolderPath contains "\\tomcat") and (InitiatingProcessFolderPath endswith "\\java.exe" or InitiatingProcessFolderPath endswith "\\javaw.exe")) or ((ProcessCommandLine contains "catalina.jar" or ProcessCommandLine contains "CATALINA_HOME") and (InitiatingProcessFolderPath endswith "\\java.exe" or InitiatingProcessFolderPath endswith "\\javaw.exe")) or (InitiatingProcessFolderPath endswith "\\caddy.exe" or InitiatingProcessFolderPath endswith "\\httpd.exe" or InitiatingProcessFolderPath endswith "\\nginx.exe" or InitiatingProcessFolderPath endswith "\\php-cgi.exe" or InitiatingProcessFolderPath endswith "\\w3wp.exe" or InitiatingProcessFolderPath endswith "\\ws_tomcatservice.exe")) and ((ProcessCommandLine contains "rundll32" and ProcessCommandLine contains "comsvcs") or (ProcessCommandLine contains " -hp" and ProcessCommandLine contains " a " and ProcessCommandLine contains " -m") or (ProcessCommandLine contains "net" and ProcessCommandLine contains " user " and ProcessCommandLine contains " /add") or (ProcessCommandLine contains "net" and ProcessCommandLine contains " localgroup " and ProcessCommandLine contains " administrators " and ProcessCommandLine contains "/add") or (FolderPath endswith "\\ntdsutil.exe" or FolderPath endswith "\\ldifde.exe" or FolderPath endswith "\\adfind.exe" or FolderPath endswith "\\procdump.exe" or FolderPath endswith "\\Nanodump.exe" or FolderPath endswith "\\vssadmin.exe" or FolderPath endswith "\\fsutil.exe") or (ProcessCommandLine contains " -decode " or ProcessCommandLine contains " -NoP " or ProcessCommandLine contains " -W Hidden " or ProcessCommandLine contains " /decode " or ProcessCommandLine contains " /ticket:" or ProcessCommandLine contains " sekurlsa" or ProcessCommandLine contains ".dmp full" or ProcessCommandLine contains ".downloadfile(" or ProcessCommandLine contains ".downloadstring(" or ProcessCommandLine contains "FromBase64String" or ProcessCommandLine contains "process call create" or ProcessCommandLine contains "reg save " or ProcessCommandLine contains "whoami /priv"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "Discovery"]
  techniques                 = ["T1505", "T1018", "T1033", "T1087"]
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