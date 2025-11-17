resource "azurerm_sentinel_alert_rule_scheduled" "potential_dridex_activity" {
  name                       = "potential_dridex_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Dridex Activity"
  description                = "Detects potential Dridex acitvity via specific process patterns - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((ProcessCommandLine contains "C:\\Users\\" and ProcessCommandLine contains "\\Desktop\\") and FolderPath endswith "\\svchost.exe") and (not(InitiatingProcessFolderPath startswith "C:\\Windows\\System32\\"))) or (((ProcessCommandLine contains " -s " or ProcessCommandLine contains "\\AppData\\Local\\Temp\\") and FolderPath endswith "\\regsvr32.exe" and InitiatingProcessFolderPath endswith "\\excel.exe") and (not(ProcessCommandLine contains ".dll"))) or (InitiatingProcessFolderPath endswith "\\svchost.exe" and ((ProcessCommandLine contains " /all" and FolderPath endswith "\\whoami.exe") or (ProcessCommandLine contains " view" and (FolderPath endswith "\\net.exe" or FolderPath endswith "\\net1.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation", "Discovery"]
  techniques                 = ["T1055", "T1135", "T1033"]
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