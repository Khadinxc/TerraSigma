resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_ping_del_command_combination" {
  name                       = "suspicious_ping_del_command_combination"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Ping/Del Command Combination"
  description                = "Detects a method often used by ransomware. Which combines the \"ping\" to wait a couple of seconds and then \"del\" to delete the file in question. Its used to hide the file responsible for the initial infection for example"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "ping" and ProcessCommandLine contains "del ") and (ProcessCommandLine contains " -n " or ProcessCommandLine contains " /n " or ProcessCommandLine contains " –n " or ProcessCommandLine contains " —n " or ProcessCommandLine contains " ―n ") and (ProcessCommandLine contains " -f " or ProcessCommandLine contains " /f " or ProcessCommandLine contains " –f " or ProcessCommandLine contains " —f " or ProcessCommandLine contains " ―f " or ProcessCommandLine contains " -q " or ProcessCommandLine contains " /q " or ProcessCommandLine contains " –q " or ProcessCommandLine contains " —q " or ProcessCommandLine contains " ―q ") and ProcessCommandLine contains "Nul"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1070"]
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
}