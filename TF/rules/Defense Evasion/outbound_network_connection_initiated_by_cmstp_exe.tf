resource "azurerm_sentinel_alert_rule_scheduled" "outbound_network_connection_initiated_by_cmstp_exe" {
  name                       = "outbound_network_connection_initiated_by_cmstp_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Outbound Network Connection Initiated By Cmstp.EXE"
  description                = "Detects a network connection initiated by Cmstp.EXE Its uncommon for \"cmstp.exe\" to initiate an outbound network connection. Investigate the source of such requests to determine if they are malicious."
  severity                   = "High"
  query                      = <<QUERY
DeviceNetworkEvents
| where InitiatingProcessFolderPath endswith "\\cmstp.exe" and (not((ipv4_is_in_range(RemoteIP, "127.0.0.0/8") or ipv4_is_in_range(RemoteIP, "10.0.0.0/8") or ipv4_is_in_range(RemoteIP, "172.16.0.0/12") or ipv4_is_in_range(RemoteIP, "192.168.0.0/16") or ipv4_is_in_range(RemoteIP, "169.254.0.0/16") or ipv4_is_in_range(RemoteIP, "::1/128") or ipv4_is_in_range(RemoteIP, "fe80::/10") or ipv4_is_in_range(RemoteIP, "fc00::/7"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "RemoteIP"
    }
  }
}