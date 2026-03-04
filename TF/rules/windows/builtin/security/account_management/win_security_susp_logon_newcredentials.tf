resource "azurerm_sentinel_alert_rule_scheduled" "win_security_susp_logon_newcredentials" {
  name                       = "win_security_susp_logon_newcredentials"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Outgoing Logon with New Credentials"
  description                = "Detects logon events that specify new credentials Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/account_management/win_security_susp_logon_newcredentials.yml - Legitimate remote administration activity | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/account_management/win_security_susp_logon_newcredentials.yml"
  severity                   = "Low"
  query                      = <<QUERY
DeviceLogonEvents
| where LogonType == 9
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "LateralMovement"]
  techniques                 = ["T1550"]
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
      column_name = "AccountName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "AccountDomain"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "AccountSid"
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
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "RemoteIP"
    }
  }
}