resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_sharpwsus_wsuspendu_execution" {
  name                       = "hacktool_sharpwsus_wsuspendu_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - SharpWSUS/WSUSpendu Execution"
  description                = "Detects the execution of SharpWSUS or WSUSpendu, utilities that allow for lateral movement through WSUS. Windows Server Update Services (WSUS) is a critical component of Windows systems and is frequently configured in a way that allows an attacker to circumvent internal networking limitations."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -Inject " and (ProcessCommandLine contains " -PayloadArgs " or ProcessCommandLine contains " -PayloadFile ")) or ((ProcessCommandLine contains " approve " or ProcessCommandLine contains " create " or ProcessCommandLine contains " check " or ProcessCommandLine contains " delete ") and (ProcessCommandLine contains " /payload:" or ProcessCommandLine contains " /payload=" or ProcessCommandLine contains " /updateid:" or ProcessCommandLine contains " /updateid="))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "LateralMovement"]
  techniques                 = ["T1210"]
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