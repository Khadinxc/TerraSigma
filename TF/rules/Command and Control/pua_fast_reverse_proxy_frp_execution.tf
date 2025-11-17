resource "azurerm_sentinel_alert_rule_scheduled" "pua_fast_reverse_proxy_frp_execution" {
  name                       = "pua_fast_reverse_proxy_frp_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - Fast Reverse Proxy (FRP) Execution"
  description                = "Detects the use of Fast Reverse Proxy. frp is a fast reverse proxy to help you expose a local server behind a NAT or firewall to the Internet. - Legitimate use"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "\\frpc.ini" or (MD5 startswith "7D9C233B8C9E3F0EA290D2B84593C842" or SHA1 startswith "06DDC9280E1F1810677935A2477012960905942F" or SHA256 startswith "57B0936B8D336D8E981C169466A15A5FD21A7D5A2C7DAF62D5E142EE860E387C") or (FolderPath endswith "\\frpc.exe" or FolderPath endswith "\\frps.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1090"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
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