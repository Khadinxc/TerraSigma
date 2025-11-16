resource "azurerm_sentinel_alert_rule_scheduled" "virtualbox_driver_installation_or_starting_of_vms" {
  name                       = "virtualbox_driver_installation_or_starting_of_vms"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Virtualbox Driver Installation or Starting of VMs"
  description                = "Adversaries can carry out malicious operations using a virtual instance to avoid detection. This rule is built to detect the registration of the Virtualbox driver or start of a Virtualbox VM. - This may have false positives on hosts where Virtualbox is legitimately being used for operations"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "VBoxRT.dll,RTR3Init" or ProcessCommandLine contains "VBoxC.dll" or ProcessCommandLine contains "VBoxDrv.sys") or (ProcessCommandLine contains "startvm" or ProcessCommandLine contains "controlvm")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1564"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }
}