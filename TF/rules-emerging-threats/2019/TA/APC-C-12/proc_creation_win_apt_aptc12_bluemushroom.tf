resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_apt_aptc12_bluemushroom" {
  name                       = "proc_creation_win_apt_aptc12_bluemushroom"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential APT-C-12 BlueMushroom DLL Load Activity Via Regsvr32"
  description                = <<DESC
    Detects potential BlueMushroom DLL loading activity via regsvr32 from AppData Local

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2019/TA/APC-C-12/proc_creation_win_apt_aptc12_bluemushroom.yml
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "regsvr32" and ProcessCommandLine contains "\\AppData\\Local\\" and ProcessCommandLine contains ".dll" and ProcessCommandLine contains ",DllEntry"
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