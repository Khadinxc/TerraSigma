resource "azurerm_sentinel_alert_rule_scheduled" "install_new_package_via_winget_local_manifest" {
  name                       = "install_new_package_via_winget_local_manifest"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Install New Package Via Winget Local Manifest"
  description                = "Detects usage of winget to install applications via manifest file. Adversaries can abuse winget to download payloads remotely and execute them. The manifest option enables you to install an application by passing in a YAML file directly to the client. Winget can be used to download and install exe, msi or msix files later. - Some false positives are expected in some environment that may use this functionality to install and test their custom applications"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\winget.exe" or ProcessVersionInfoOriginalFileName =~ "winget.exe") and (ProcessCommandLine contains "install" or ProcessCommandLine contains " add ") and (ProcessCommandLine contains "-m " or ProcessCommandLine contains "--manifest")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
  techniques                 = ["T1059"]
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