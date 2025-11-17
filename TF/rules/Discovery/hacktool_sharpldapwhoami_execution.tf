resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_sharpldapwhoami_execution" {
  name                       = "hacktool_sharpldapwhoami_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - SharpLdapWhoami Execution"
  description                = "Detects SharpLdapWhoami, a whoami alternative that queries the LDAP service on a domain controller - Programs that use the same command line flags"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine endswith " /method:ntlm" or ProcessCommandLine endswith " /method:kerb" or ProcessCommandLine endswith " /method:nego" or ProcessCommandLine endswith " /m:nego" or ProcessCommandLine endswith " /m:ntlm" or ProcessCommandLine endswith " /m:kerb") or FolderPath endswith "\\SharpLdapWhoami.exe" or (ProcessVersionInfoOriginalFileName contains "SharpLdapWhoami" or ProcessVersionInfoProductName =~ "SharpLdapWhoami")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1033"]
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