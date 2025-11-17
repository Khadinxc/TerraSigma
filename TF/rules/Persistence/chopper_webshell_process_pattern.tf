resource "azurerm_sentinel_alert_rule_scheduled" "chopper_webshell_process_pattern" {
  name                       = "chopper_webshell_process_pattern"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Chopper Webshell Process Pattern"
  description                = "Detects patterns found in process executions cause by China Chopper like tiny (ASPX) webshells"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "&ipconfig&echo" or ProcessCommandLine contains "&quser&echo" or ProcessCommandLine contains "&whoami&echo" or ProcessCommandLine contains "&c:&echo" or ProcessCommandLine contains "&cd&echo" or ProcessCommandLine contains "&dir&echo" or ProcessCommandLine contains "&echo [E]" or ProcessCommandLine contains "&echo [S]") and (FolderPath endswith "\\w3wp.exe" or InitiatingProcessFolderPath endswith "\\w3wp.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "Discovery"]
  techniques                 = ["T1505", "T1018", "T1033", "T1087"]
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