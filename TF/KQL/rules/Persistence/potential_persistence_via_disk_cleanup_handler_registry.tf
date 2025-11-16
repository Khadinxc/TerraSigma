resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_disk_cleanup_handler_registry" {
  name                       = "potential_persistence_via_disk_cleanup_handler_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via Disk Cleanup Handler - Registry"
  description                = "Detects when an attacker modifies values of the Disk Cleanup Handler in the registry to achieve persistence. The disk cleanup manager is part of the operating system. It displays the dialog box […] The user has the option of enabling or disabling individual handlers by selecting or clearing their check box in the disk cleanup manager's UI. Although Windows comes with a number of disk cleanup handlers, they aren't designed to handle files produced by other applications. Instead, the disk cleanup manager is designed to be flexible and extensible by enabling any developer to implement and register their own disk cleanup handler. Any developer can extend the available disk cleanup services by implementing and registering a disk cleanup handler. - Legitimate new entry added by windows"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (ActionType =~ "RegistryKeyCreated" and RegistryKey endswith "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VolumeCaches*") and (not((RegistryKey endswith "\\Active Setup Temp Folders" or RegistryKey endswith "\\BranchCache" or RegistryKey endswith "\\Content Indexer Cleaner" or RegistryKey endswith "\\D3D Shader Cache" or RegistryKey endswith "\\Delivery Optimization Files" or RegistryKey endswith "\\Device Driver Packages" or RegistryKey endswith "\\Diagnostic Data Viewer database files" or RegistryKey endswith "\\Downloaded Program Files" or RegistryKey endswith "\\DownloadsFolder" or RegistryKey endswith "\\Feedback Hub Archive log files" or RegistryKey endswith "\\Internet Cache Files" or RegistryKey endswith "\\Language Pack" or RegistryKey endswith "\\Microsoft Office Temp Files" or RegistryKey endswith "\\Offline Pages Files" or RegistryKey endswith "\\Old ChkDsk Files" or RegistryKey endswith "\\Previous Installations" or RegistryKey endswith "\\Recycle Bin" or RegistryKey endswith "\\RetailDemo Offline Content" or RegistryKey endswith "\\Setup Log Files" or RegistryKey endswith "\\System error memory dump files" or RegistryKey endswith "\\System error minidump files" or RegistryKey endswith "\\Temporary Files" or RegistryKey endswith "\\Temporary Setup Files" or RegistryKey endswith "\\Temporary Sync Files" or RegistryKey endswith "\\Thumbnail Cache" or RegistryKey endswith "\\Update Cleanup" or RegistryKey endswith "\\Upgrade Discarded Files" or RegistryKey endswith "\\User file versions" or RegistryKey endswith "\\Windows Defender" or RegistryKey endswith "\\Windows Error Reporting Files" or RegistryKey endswith "\\Windows ESD installation files" or RegistryKey endswith "\\Windows Upgrade Log Files")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
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
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }
}