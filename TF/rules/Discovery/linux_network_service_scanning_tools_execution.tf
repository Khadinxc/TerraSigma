resource "azurerm_sentinel_alert_rule_scheduled" "linux_network_service_scanning_tools_execution" {
  name                       = "linux_network_service_scanning_tools_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Linux Network Service Scanning Tools Execution"
  description                = "Detects execution of network scanning and reconnaisance tools. These tools can be used for the enumeration of local or remote network services for example. - Legitimate administration activities"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "/nc" or FolderPath endswith "/ncat" or FolderPath endswith "/netcat" or FolderPath endswith "/socat") and (not((ProcessCommandLine contains " --listen " or ProcessCommandLine contains " -l ")))) or (FolderPath endswith "/autorecon" or FolderPath endswith "/hping" or FolderPath endswith "/hping2" or FolderPath endswith "/hping3" or FolderPath endswith "/naabu" or FolderPath endswith "/nmap" or FolderPath endswith "/nping" or FolderPath endswith "/telnet" or FolderPath endswith "/zenmap")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1046"]
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