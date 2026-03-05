resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_susp_execution_path_webserver" {
  name                       = "proc_creation_win_susp_execution_path_webserver"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Execution From Webserver Root Folder"
  description                = <<DESC
    Detects a program executing from a web server root folder. Use this rule to hunt for potential interesting activity such as webshell or backdoors

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-threat-hunting/windows/process_creation/proc_creation_win_susp_execution_path_webserver.yml

    False Positives:
    - Various applications
    - Tools that include ping or nslookup command invocations
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath contains "\\wwwroot\\" or FolderPath contains "\\wmpub\\" or FolderPath contains "\\htdocs\\") and (not(((FolderPath contains "bin\\" or FolderPath contains "\\Tools\\" or FolderPath contains "\\SMSComponent\\") and InitiatingProcessFolderPath endswith "\\services.exe")))
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
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}