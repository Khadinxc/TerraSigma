resource "azurerm_sentinel_alert_rule_scheduled" "pua_nps_tunneling_tool_execution" {
  name                       = "pua_nps_tunneling_tool_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - NPS Tunneling Tool Execution"
  description                = "Detects the use of NPS, a port forwarding and intranet penetration proxy server - Legitimate use"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -server=" and ProcessCommandLine contains " -vkey=" and ProcessCommandLine contains " -password=") or ProcessCommandLine contains " -config=npc" or (MD5 startswith "AE8ACF66BFE3A44148964048B826D005" or SHA1 startswith "CEA49E9B9B67F3A13AD0BE1C2655293EA3C18181" or SHA256 startswith "5A456283392FFCEEEACA3D3426C306EB470304637520D72FED1CC1FEBBBD6856") or FolderPath endswith "\\npc.exe"
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