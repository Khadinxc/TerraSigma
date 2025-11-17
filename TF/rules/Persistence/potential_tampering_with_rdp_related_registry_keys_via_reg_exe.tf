resource "azurerm_sentinel_alert_rule_scheduled" "potential_tampering_with_rdp_related_registry_keys_via_reg_exe" {
  name                       = "potential_tampering_with_rdp_related_registry_keys_via_reg_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Tampering With RDP Related Registry Keys Via Reg.EXE"
  description                = "Detects the execution of \"reg.exe\" for enabling/disabling the RDP service on the host by tampering with the 'CurrentControlSet\\Control\\Terminal Server' values"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " add " and ProcessCommandLine contains "\\CurrentControlSet\\Control\\Terminal Server" and ProcessCommandLine contains "REG_DWORD" and ProcessCommandLine contains " /f") and (FolderPath endswith "\\reg.exe" or ProcessVersionInfoOriginalFileName =~ "reg.exe")) and ((ProcessCommandLine contains "Licensing Core" and ProcessCommandLine contains "EnableConcurrentSessions") or (ProcessCommandLine contains "WinStations\\RDP-Tcp" or ProcessCommandLine contains "MaxInstanceCount" or ProcessCommandLine contains "fEnableWinStation" or ProcessCommandLine contains "TSUserEnabled" or ProcessCommandLine contains "TSEnabled" or ProcessCommandLine contains "TSAppCompat" or ProcessCommandLine contains "IdleWinStationPoolCount" or ProcessCommandLine contains "TSAdvertise" or ProcessCommandLine contains "AllowTSConnections" or ProcessCommandLine contains "fSingleSessionPerUser" or ProcessCommandLine contains "fDenyTSConnections"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion", "LateralMovement"]
  techniques                 = ["T1021", "T1112"]
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
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}