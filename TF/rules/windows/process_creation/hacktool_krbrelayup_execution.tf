resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_krbrelayup_execution" {
  name                       = "hacktool_krbrelayup_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - KrbRelayUp Execution"
  description                = "Detects KrbRelayUp used to perform a universal no-fix local privilege escalation in Windows domain environments where LDAP signing is not enforced - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " relay " and ProcessCommandLine contains " -Domain " and ProcessCommandLine contains " -ComputerName ") or (ProcessCommandLine contains " krbscm " and ProcessCommandLine contains " -sc ") or (ProcessCommandLine contains " spawn " and ProcessCommandLine contains " -d " and ProcessCommandLine contains " -cn " and ProcessCommandLine contains " -cp ") or (FolderPath endswith "\\KrbRelayUp.exe" or ProcessVersionInfoOriginalFileName =~ "KrbRelayUp.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CredentialAccess", "LateralMovement"]
  techniques                 = ["T1558", "T1550"]
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