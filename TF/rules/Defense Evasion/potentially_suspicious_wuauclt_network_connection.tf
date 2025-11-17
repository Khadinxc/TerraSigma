resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_wuauclt_network_connection" {
  name                       = "potentially_suspicious_wuauclt_network_connection"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Wuauclt Network Connection"
  description                = "Detects the use of the Windows Update Client binary (wuauclt.exe) to proxy execute code and making network connections. One could easily make the DLL spawn a new process and inject to it to proxy the network connection and bypass this rule."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceNetworkEvents
| where (InitiatingProcessCommandLine contains " /RunHandlerComServer" and InitiatingProcessFolderPath contains "wuauclt") and (not((InitiatingProcessCommandLine =~ "" or isnull(InitiatingProcessCommandLine) or (ipv4_is_in_range(RemoteIP, "127.0.0.0/8") or ipv4_is_in_range(RemoteIP, "10.0.0.0/8") or ipv4_is_in_range(RemoteIP, "169.254.0.0/16") or ipv4_is_in_range(RemoteIP, "172.16.0.0/12") or ipv4_is_in_range(RemoteIP, "192.168.0.0/16") or ipv4_is_in_range(RemoteIP, "::1/128") or ipv4_is_in_range(RemoteIP, "fe80::/10") or ipv4_is_in_range(RemoteIP, "fc00::/7")) or (ipv4_is_in_range(RemoteIP, "20.184.0.0/13") or ipv4_is_in_range(RemoteIP, "20.192.0.0/10") or ipv4_is_in_range(RemoteIP, "23.79.0.0/16") or ipv4_is_in_range(RemoteIP, "51.10.0.0/15") or ipv4_is_in_range(RemoteIP, "51.103.0.0/16") or ipv4_is_in_range(RemoteIP, "51.104.0.0/15") or ipv4_is_in_range(RemoteIP, "52.224.0.0/11")) or (InitiatingProcessCommandLine contains ":\\Windows\\UUS\\Packages\\Preview\\amd64\\updatedeploy.dll /ClassId" or InitiatingProcessCommandLine contains ":\\Windows\\UUS\\amd64\\UpdateDeploy.dll /ClassId") or (InitiatingProcessCommandLine contains ":\\Windows\\WinSxS\\" and InitiatingProcessCommandLine contains "\\UpdateDeploy.dll /ClassId "))))
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

  entity_mapping {
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "InitiatingProcessCommandLine"
    }
  }
}