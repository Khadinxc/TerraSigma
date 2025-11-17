resource "azurerm_sentinel_alert_rule_scheduled" "persistence_via_disk_cleanup_handler_autorun" {
  name                       = "persistence_via_disk_cleanup_handler_autorun"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Persistence Via Disk Cleanup Handler - Autorun"
  description                = "Detects when an attacker modifies values of the Disk Cleanup Handler in the registry to achieve persistence via autorun. The disk cleanup manager is part of the operating system. It displays the dialog box […] The user has the option of enabling or disabling individual handlers by selecting or clearing their check box in the disk cleanup manager's UI. Although Windows comes with a number of disk cleanup handlers, they aren't designed to handle files produced by other applications. Instead, the disk cleanup manager is designed to be flexible and extensible by enabling any developer to implement and register their own disk cleanup handler. Any developer can extend the available disk cleanup services by implementing and registering a disk cleanup handler."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VolumeCaches*" and ((RegistryValueData =~ "DWORD (0x00000001)" and RegistryKey contains "\\Autorun") or ((RegistryValueData contains "cmd" or RegistryValueData contains "powershell" or RegistryValueData contains "rundll32" or RegistryValueData contains "mshta" or RegistryValueData contains "cscript" or RegistryValueData contains "wscript" or RegistryValueData contains "wsl" or RegistryValueData contains "\\Users\\Public\\" or RegistryValueData contains "\\Windows\\TEMP\\" or RegistryValueData contains "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\") and (RegistryKey contains "\\CleanupString" or RegistryKey contains "\\PreCleanupString")))
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
    entity_type = "RegistryKey"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }

  entity_mapping {
    entity_type = "RegistryValue"
    field_mapping {
      identifier  = "Value"
      column_name = "RegistryValueData"
    }
  }
}