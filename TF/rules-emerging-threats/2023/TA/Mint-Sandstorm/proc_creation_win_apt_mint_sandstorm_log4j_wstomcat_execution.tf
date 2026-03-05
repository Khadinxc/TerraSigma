resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_apt_mint_sandstorm_log4j_wstomcat_execution" {
  name                       = "proc_creation_win_apt_mint_sandstorm_log4j_wstomcat_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Mint Sandstorm - Log4J Wstomcat Process Execution"
  description                = <<DESC
    Detects Log4J Wstomcat process execution as seen in Mint Sandstorm activity

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2023/TA/Mint-Sandstorm/proc_creation_win_apt_mint_sandstorm_log4j_wstomcat_execution.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\ws_tomcatservice.exe" and (not(FolderPath endswith "\\repadmin.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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