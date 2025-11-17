resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_certipy_execution" {
  name                       = "hacktool_certipy_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - Certipy Execution"
  description                = "Detects Certipy execution, a tool for Active Directory Certificate Services enumeration and abuse based on PE metadata characteristics and common command line arguments. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\Certipy.exe" or ProcessVersionInfoOriginalFileName =~ "Certipy.exe" or ProcessVersionInfoFileDescription contains "Certipy") or ((ProcessCommandLine contains " account " or ProcessCommandLine contains " auth " or ProcessCommandLine contains " cert " or ProcessCommandLine contains " find " or ProcessCommandLine contains " forge " or ProcessCommandLine contains " ptt " or ProcessCommandLine contains " relay " or ProcessCommandLine contains " req " or ProcessCommandLine contains " shadow " or ProcessCommandLine contains " template ") and (ProcessCommandLine contains " -bloodhound" or ProcessCommandLine contains " -ca-pfx " or ProcessCommandLine contains " -dc-ip " or ProcessCommandLine contains " -kirbi" or ProcessCommandLine contains " -old-bloodhound" or ProcessCommandLine contains " -pfx " or ProcessCommandLine contains " -target" or ProcessCommandLine contains " -template" or ProcessCommandLine contains " -username " or ProcessCommandLine contains " -vulnerable" or ProcessCommandLine contains "auth -pfx" or ProcessCommandLine contains "shadow auto" or ProcessCommandLine contains "shadow list"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery", "CredentialAccess"]
  techniques                 = ["T1649"]
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