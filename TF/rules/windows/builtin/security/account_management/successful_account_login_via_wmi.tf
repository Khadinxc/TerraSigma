resource "azurerm_sentinel_alert_rule_scheduled" "successful_account_login_via_wmi" {
  name                       = "successful_account_login_via_wmi"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Successful Account Login Via WMI"
  description                = "Detects successful logon attempts performed with WMI - Monitoring tools - Legitimate system administration"
  severity                   = "Low"
  query                      = <<QUERY
DeviceLogonEvents
| where InitiatingProcessFolderPath endswith "\\WmiPrvSE.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1047"]
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
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "RemoteIP"
    }
  }
}