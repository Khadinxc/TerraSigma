resource "azurerm_sentinel_alert_rule_scheduled" "disabling_security_tools" {
  name                       = "disabling_security_tools"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Disabling Security Tools"
  description                = "Detects disabling security tools - Legitimate administration activities"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "cbdaemon" and ProcessCommandLine contains "stop") and FolderPath endswith "/service") or ((ProcessCommandLine contains "cbdaemon" and ProcessCommandLine contains "off") and FolderPath endswith "/chkconfig") or ((ProcessCommandLine contains "cbdaemon" and ProcessCommandLine contains "stop") and FolderPath endswith "/systemctl") or ((ProcessCommandLine contains "cbdaemon" and ProcessCommandLine contains "disable") and FolderPath endswith "/systemctl") or ((ProcessCommandLine contains "stop" and ProcessCommandLine contains "falcon-sensor") and FolderPath endswith "/systemctl") or ((ProcessCommandLine contains "disable" and ProcessCommandLine contains "falcon-sensor") and FolderPath endswith "/systemctl") or ((ProcessCommandLine contains "firewalld" and ProcessCommandLine contains "stop") and FolderPath endswith "/systemctl") or ((ProcessCommandLine contains "firewalld" and ProcessCommandLine contains "disable") and FolderPath endswith "/systemctl") or ((ProcessCommandLine contains "iptables" and ProcessCommandLine contains "stop") and FolderPath endswith "/service") or ((ProcessCommandLine contains "ip6tables" and ProcessCommandLine contains "stop") and FolderPath endswith "/service") or ((ProcessCommandLine contains "iptables" and ProcessCommandLine contains "stop") and FolderPath endswith "/chkconfig") or ((ProcessCommandLine contains "ip6tables" and ProcessCommandLine contains "stop") and FolderPath endswith "/chkconfig") or (ProcessCommandLine contains "0" and FolderPath endswith "/setenforce")
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