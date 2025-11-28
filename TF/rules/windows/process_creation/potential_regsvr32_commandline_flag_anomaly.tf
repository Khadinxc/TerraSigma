resource "azurerm_sentinel_alert_rule_scheduled" "potential_regsvr32_commandline_flag_anomaly" {
  name                       = "potential_regsvr32_commandline_flag_anomaly"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Regsvr32 Commandline Flag Anomaly"
  description                = "Detects a potential command line flag anomaly related to \"regsvr32\" in which the \"/i\" flag is used without the \"/n\" which should be uncommon. - Administrator typo might cause some false positives"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " -i:" or ProcessCommandLine contains " /i:" or ProcessCommandLine contains " –i:" or ProcessCommandLine contains " —i:" or ProcessCommandLine contains " ―i:") and FolderPath endswith "\\regsvr32.exe") and (not(ProcessCommandLine contains " -n " or ProcessCommandLine contains " /n " or ProcessCommandLine contains " –n " or ProcessCommandLine contains " —n " or ProcessCommandLine contains " ―n "))
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