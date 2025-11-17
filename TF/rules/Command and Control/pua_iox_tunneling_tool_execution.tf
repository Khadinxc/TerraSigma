resource "azurerm_sentinel_alert_rule_scheduled" "pua_iox_tunneling_tool_execution" {
  name                       = "pua_iox_tunneling_tool_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA- IOX Tunneling Tool Execution"
  description                = "Detects the use of IOX - a tool for port forwarding and intranet proxy purposes - Legitimate use"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\iox.exe" or (ProcessCommandLine contains ".exe fwd -l " or ProcessCommandLine contains ".exe fwd -r " or ProcessCommandLine contains ".exe proxy -l " or ProcessCommandLine contains ".exe proxy -r ") or (MD5 startswith "9DB2D314DD3F704A02051EF5EA210993" or SHA1 startswith "039130337E28A6623ECF9A0A3DA7D92C5964D8DD" or SHA256 startswith "C6CF82919B809967D9D90EA73772A8AA1C1EB3BC59252D977500F64F1A0D6731")
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