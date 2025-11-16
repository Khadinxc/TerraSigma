resource "azurerm_sentinel_alert_rule_scheduled" "linux_webshell_indicators" {
  name                       = "linux_webshell_indicators"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Linux Webshell Indicators"
  description                = "Detects suspicious sub processes of web server processes - Web applications that invoke Linux command line tools"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((InitiatingProcessFolderPath endswith "/httpd" or InitiatingProcessFolderPath endswith "/lighttpd" or InitiatingProcessFolderPath endswith "/nginx" or InitiatingProcessFolderPath endswith "/apache2" or InitiatingProcessFolderPath endswith "/node" or InitiatingProcessFolderPath endswith "/caddy") or (InitiatingProcessCommandLine contains "/bin/java" and InitiatingProcessCommandLine contains "tomcat") or (InitiatingProcessCommandLine contains "/bin/java" and InitiatingProcessCommandLine contains "websphere")) and (FolderPath endswith "/whoami" or FolderPath endswith "/ifconfig" or FolderPath endswith "/ip" or FolderPath endswith "/bin/uname" or FolderPath endswith "/bin/cat" or FolderPath endswith "/bin/crontab" or FolderPath endswith "/hostname" or FolderPath endswith "/iptables" or FolderPath endswith "/netstat" or FolderPath endswith "/pwd" or FolderPath endswith "/route")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
  techniques                 = ["T1505"]
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