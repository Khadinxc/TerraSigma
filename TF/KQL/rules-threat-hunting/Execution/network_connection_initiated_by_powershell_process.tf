resource "azurerm_sentinel_alert_rule_scheduled" "network_connection_initiated_by_powershell_process" {
  name                       = "network_connection_initiated_by_powershell_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Network Connection Initiated By PowerShell Process"
  description                = "Detects a network connection that was initiated from a PowerShell process. Often times malicious powershell scripts download additional payloads or communicate back to command and control channels via uncommon ports or IPs. Use this rule as a basis for hunting for anomalies. - Administrative scripts - Microsoft IP range - Additional filters are required. Adjust to your environment (e.g. extend filters with company's ip range')"
  severity                   = "Low"
  query                      = <<QUERY
DeviceNetworkEvents
| where (InitiatingProcessFolderPath endswith "\\powershell.exe" or InitiatingProcessFolderPath endswith "\\pwsh.exe") and (not((((ipv4_is_in_range(RemoteIP, "127.0.0.0/8") or ipv4_is_in_range(RemoteIP, "10.0.0.0/8") or ipv4_is_in_range(RemoteIP, "169.254.0.0/16") or ipv4_is_in_range(RemoteIP, "172.16.0.0/12") or ipv4_is_in_range(RemoteIP, "192.168.0.0/16") or ipv4_is_in_range(RemoteIP, "::1/128") or ipv4_is_in_range(RemoteIP, "fe80::/10") or ipv4_is_in_range(RemoteIP, "fc00::/7")) and (InitiatingProcessAccountName contains "AUTHORI" or InitiatingProcessAccountName contains "AUTORI")) or (ipv4_is_in_range(RemoteIP, "20.184.0.0/13") or ipv4_is_in_range(RemoteIP, "51.103.210.0/23")))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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
  }

  entity_mapping {
    entity_type = "Process"
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