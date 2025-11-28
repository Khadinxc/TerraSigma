resource "azurerm_sentinel_alert_rule_scheduled" "potential_recon_activity_via_nltest_exe" {
  name                       = "potential_recon_activity_via_nltest_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Recon Activity Via Nltest.EXE"
  description                = "Detects nltest commands that can be used for information discovery - Legitimate administration use but user and host must be investigated"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\nltest.exe" or ProcessVersionInfoOriginalFileName =~ "nltestrk.exe") and ((ProcessCommandLine contains "server" and ProcessCommandLine contains "query") or (ProcessCommandLine contains "/user" or ProcessCommandLine contains "all_trusts" or ProcessCommandLine contains "dclist:" or ProcessCommandLine contains "dnsgetdc:" or ProcessCommandLine contains "domain_trusts" or ProcessCommandLine contains "dsgetdc:" or ProcessCommandLine contains "parentdomain" or ProcessCommandLine contains "trusted_domains"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1016", "T1482"]
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