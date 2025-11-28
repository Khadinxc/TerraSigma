resource "azurerm_sentinel_alert_rule_scheduled" "python_webserver_execution_linux" {
  name                       = "python_webserver_execution_linux"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Python WebServer Execution - Linux"
  description                = "Detects the execution of Python web servers via command line interface (CLI). After gaining access to target systems, adversaries may use Python's built-in HTTP server modules to quickly establish a web server without requiring additional software. This technique is commonly used in post-exploitation scenarios as it provides a simple method for transferring files between the compromised host and attacker-controlled systems. - Testing or development activity"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "/python" or FolderPath endswith "/python2" or FolderPath endswith "/python3") or (FolderPath contains "/python2." or FolderPath contains "/python3.")) and (ProcessCommandLine contains "http.server" or ProcessCommandLine contains "SimpleHTTPServer")
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