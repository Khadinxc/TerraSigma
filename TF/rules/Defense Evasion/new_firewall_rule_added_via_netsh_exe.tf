resource "azurerm_sentinel_alert_rule_scheduled" "new_firewall_rule_added_via_netsh_exe" {
  name                       = "new_firewall_rule_added_via_netsh_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New Firewall Rule Added Via Netsh.EXE"
  description                = "Detects the addition of a new rule to the Windows firewall via netsh - Legitimate administration activity - Software installations"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " firewall " and ProcessCommandLine contains " add ") and (FolderPath endswith "\\netsh.exe" or ProcessVersionInfoOriginalFileName =~ "netsh.exe")) and (not(((ProcessCommandLine contains "advfirewall firewall add rule name=Dropbox dir=in action=allow \"program=" and ProcessCommandLine contains ":\\Program Files (x86)\\Dropbox\\Client\\Dropbox.exe\" enable=yes profile=Any") or (ProcessCommandLine contains "advfirewall firewall add rule name=Dropbox dir=in action=allow \"program=" and ProcessCommandLine contains ":\\Program Files\\Dropbox\\Client\\Dropbox.exe\" enable=yes profile=Any"))))
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
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}