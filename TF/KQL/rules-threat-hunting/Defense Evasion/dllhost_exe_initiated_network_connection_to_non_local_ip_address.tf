resource "azurerm_sentinel_alert_rule_scheduled" "dllhost_exe_initiated_network_connection_to_non_local_ip_address" {
  name                       = "dllhost_exe_initiated_network_connection_to_non_local_ip_address"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Dllhost.EXE Initiated Network Connection To Non-Local IP Address"
  description                = "Detects Dllhost.EXE initiating a network connection to a non-local IP address. Aside from Microsoft own IP range that needs to be excluded. Network communication from Dllhost will depend entirely on the hosted DLL. An initial baseline is recommended before deployment. - Communication to other corporate systems that use IP addresses from public address spaces"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceNetworkEvents
| where InitiatingProcessFolderPath endswith "\\dllhost.exe" and (not(((ipv4_is_in_range(RemoteIP, "::1/128") or ipv4_is_in_range(RemoteIP, "10.0.0.0/8") or ipv4_is_in_range(RemoteIP, "127.0.0.0/8") or ipv4_is_in_range(RemoteIP, "172.16.0.0/12") or ipv4_is_in_range(RemoteIP, "192.168.0.0/16") or ipv4_is_in_range(RemoteIP, "169.254.0.0/16") or ipv4_is_in_range(RemoteIP, "fc00::/7") or ipv4_is_in_range(RemoteIP, "fe80::/10")) or (ipv4_is_in_range(RemoteIP, "20.184.0.0/13") or ipv4_is_in_range(RemoteIP, "20.192.0.0/10") or ipv4_is_in_range(RemoteIP, "23.72.0.0/13") or ipv4_is_in_range(RemoteIP, "51.10.0.0/15") or ipv4_is_in_range(RemoteIP, "51.103.0.0/16") or ipv4_is_in_range(RemoteIP, "51.104.0.0/15") or ipv4_is_in_range(RemoteIP, "52.224.0.0/11") or ipv4_is_in_range(RemoteIP, "150.171.0.0/19") or ipv4_is_in_range(RemoteIP, "204.79.197.0/24")))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
  techniques                 = ["T1218", "T1559"]
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