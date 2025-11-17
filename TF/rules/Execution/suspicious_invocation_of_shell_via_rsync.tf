resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_invocation_of_shell_via_rsync" {
  name                       = "suspicious_invocation_of_shell_via_rsync"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Invocation of Shell via Rsync"
  description                = "Detects the execution of a shell as sub process of \"rsync\" without the expected command line flag \"-e\" being used, which could be an indication of exploitation as described in CVE-2024-12084. This behavior is commonly associated with attempts to execute arbitrary commands or escalate privileges, potentially leading to unauthorized access or further exploitation."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "/ash" or FolderPath endswith "/bash" or FolderPath endswith "/csh" or FolderPath endswith "/dash" or FolderPath endswith "/ksh" or FolderPath endswith "/sh" or FolderPath endswith "/tcsh" or FolderPath endswith "/zsh") and (InitiatingProcessFolderPath endswith "/rsync" or InitiatingProcessFolderPath endswith "/rsyncd")) and (not(ProcessCommandLine contains " -e "))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059", "T1203"]
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