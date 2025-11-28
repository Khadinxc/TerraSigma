resource "azurerm_sentinel_alert_rule_scheduled" "outbound_network_connection_initiated_by_microsoft_dialer" {
  name                       = "outbound_network_connection_initiated_by_microsoft_dialer"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Outbound Network Connection Initiated By Microsoft Dialer"
  description                = "Detects outbound network connection initiated by Microsoft Dialer. The Microsoft Dialer, also known as Phone Dialer, is a built-in utility application included in various versions of the Microsoft Windows operating system. Its primary function is to provide users with a graphical interface for managing phone calls via a modem or a phone line connected to the computer. This is an outdated process in the current conext of it's usage and is a common target for info stealers for process injection, and is used to make C2 connections, common example is \"Rhadamanthys\" - In Modern Windows systems, unable to see legitimate usage of this process, However, if an organization has legitimate purpose for this there can be false positives."
  severity                   = "High"
  query                      = <<QUERY
DeviceNetworkEvents
| where InitiatingProcessFolderPath endswith ":\\Windows\\System32\\dialer.exe" and (not((ipv4_is_in_range(RemoteIP, "127.0.0.0/8") or ipv4_is_in_range(RemoteIP, "10.0.0.0/8") or ipv4_is_in_range(RemoteIP, "172.16.0.0/12") or ipv4_is_in_range(RemoteIP, "192.168.0.0/16") or ipv4_is_in_range(RemoteIP, "169.254.0.0/16") or ipv4_is_in_range(RemoteIP, "::1/128") or ipv4_is_in_range(RemoteIP, "fe80::/10") or ipv4_is_in_range(RemoteIP, "fc00::/7"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "CommandAndControl"]
  techniques                 = ["T1071"]
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