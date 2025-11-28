resource "azurerm_sentinel_alert_rule_scheduled" "new_kernel_driver_via_sc_exe" {
  name                       = "new_kernel_driver_via_sc_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New Kernel Driver Via SC.EXE"
  description                = "Detects creation of a new service (kernel driver) with the type \"kernel\" - Rare legitimate installation of kernel drivers via sc.exe"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "create" or ProcessCommandLine contains "config") and (ProcessCommandLine contains "binPath" and ProcessCommandLine contains "type" and ProcessCommandLine contains "kernel") and FolderPath endswith "\\sc.exe") and (not(((ProcessCommandLine contains "create netprotection_network_filter" and ProcessCommandLine contains "type= kernel start= " and ProcessCommandLine contains "binPath= System32\\drivers\\netprotection_network_filter" and ProcessCommandLine contains "DisplayName= netprotection_network_filter" and ProcessCommandLine contains "group= PNP_TDI tag= yes") or (ProcessCommandLine contains "create avelam binpath=C:\\Windows\\system32\\drivers\\avelam.sys" and ProcessCommandLine contains "type=kernel start=boot error=critical group=Early-Launch"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1543"]
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