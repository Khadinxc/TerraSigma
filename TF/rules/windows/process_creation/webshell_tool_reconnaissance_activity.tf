resource "azurerm_sentinel_alert_rule_scheduled" "webshell_tool_reconnaissance_activity" {
  name                       = "webshell_tool_reconnaissance_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Webshell Tool Reconnaissance Activity"
  description                = "Detects processes spawned from web servers (PHP, Tomcat, IIS, etc.) that perform reconnaissance looking for the existence of popular scripting tools (perl, python, wget) on the system via the help commands"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((InitiatingProcessFolderPath contains "-tomcat-" or InitiatingProcessFolderPath contains "\\tomcat") and (InitiatingProcessFolderPath endswith "\\java.exe" or InitiatingProcessFolderPath endswith "\\javaw.exe")) or ((ProcessCommandLine contains "CATALINA_HOME" or ProcessCommandLine contains "catalina.jar") and (InitiatingProcessFolderPath endswith "\\java.exe" or InitiatingProcessFolderPath endswith "\\javaw.exe")) or (InitiatingProcessFolderPath endswith "\\caddy.exe" or InitiatingProcessFolderPath endswith "\\httpd.exe" or InitiatingProcessFolderPath endswith "\\nginx.exe" or InitiatingProcessFolderPath endswith "\\php-cgi.exe" or InitiatingProcessFolderPath endswith "\\w3wp.exe" or InitiatingProcessFolderPath endswith "\\ws_tomcatservice.exe")) and (ProcessCommandLine contains "perl --help" or ProcessCommandLine contains "perl -h" or ProcessCommandLine contains "python --help" or ProcessCommandLine contains "python -h" or ProcessCommandLine contains "python3 --help" or ProcessCommandLine contains "python3 -h" or ProcessCommandLine contains "wget --help")
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