resource "azurerm_sentinel_alert_rule_scheduled" "new_root_certificate_installed_via_certmgr_exe" {
  name                       = "new_root_certificate_installed_via_certmgr_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New Root Certificate Installed Via CertMgr.EXE"
  description                = "Detects execution of \"certmgr\" with the \"add\" flag in order to install a new certificate on the system. Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers. - Help Desk or IT may need to manually add a corporate Root CA on occasion. Need to test if GPO push doesn't trigger FP"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "/add" and ProcessCommandLine contains "root") and (FolderPath endswith "\\CertMgr.exe" or ProcessVersionInfoOriginalFileName =~ "CERTMGT.EXE")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1553"]
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
    field_mapping {
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}