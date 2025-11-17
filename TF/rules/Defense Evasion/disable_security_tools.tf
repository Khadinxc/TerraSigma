resource "azurerm_sentinel_alert_rule_scheduled" "disable_security_tools" {
  name                       = "disable_security_tools"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Disable Security Tools"
  description                = "Detects disabling security tools - Legitimate activities"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "unload" and FolderPath =~ "/bin/launchctl") and (ProcessCommandLine contains "com.objective-see.lulu.plist" or ProcessCommandLine contains "com.objective-see.blockblock.plist" or ProcessCommandLine contains "com.google.santad.plist" or ProcessCommandLine contains "com.carbonblack.defense.daemon.plist" or ProcessCommandLine contains "com.carbonblack.daemon.plist" or ProcessCommandLine contains "at.obdev.littlesnitchd.plist" or ProcessCommandLine contains "com.tenablesecurity.nessusagent.plist" or ProcessCommandLine contains "com.opendns.osx.RoamingClientConfigUpdater.plist" or ProcessCommandLine contains "com.crowdstrike.falcond.plist" or ProcessCommandLine contains "com.crowdstrike.userdaemon.plist" or ProcessCommandLine contains "osquery" or ProcessCommandLine contains "filebeat" or ProcessCommandLine contains "auditbeat" or ProcessCommandLine contains "packetbeat" or ProcessCommandLine contains "td-agent")) or (ProcessCommandLine contains "disable" and FolderPath =~ "/usr/sbin/spctl")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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