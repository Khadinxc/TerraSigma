resource "azurerm_sentinel_alert_rule_scheduled" "python_initiated_connection" {
  name                       = "python_initiated_connection"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Python Initiated Connection"
  description                = "Detects a Python process initiating a network connection. While this often relates to package installation, it can also indicate a potential malicious script communicating with a C&C server. - Legitimate python scripts using the socket library or similar will trigger this. Apply additional filters and perform an initial baseline before deploying."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceNetworkEvents
| where (InitiatingProcessFolderPath contains "\\python" and InitiatingProcessFolderPath contains ".exe") and (not(((RemoteIP =~ "127.0.0.1" and LocalIP =~ "127.0.0.1") or (InitiatingProcessCommandLine contains "pip.exe" and InitiatingProcessCommandLine contains "install")))) and (not((((InitiatingProcessCommandLine contains ":\\ProgramData\\Anaconda3\\Scripts\\conda-script.py" and InitiatingProcessCommandLine contains "update") and InitiatingProcessParentFileName =~ "conda.exe") or (InitiatingProcessCommandLine contains "C:\\ProgramData\\Anaconda3\\Scripts\\jupyter-notebook-script.py" and InitiatingProcessParentFileName =~ "python.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1046"]
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
      column_name = "InitiatingProcessCommandLine"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "InitiatingProcessFolderPath"
    }
  }

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "RemoteIP"
    }
  }
}