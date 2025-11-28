resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_sharpdpapi_execution" {
  name                       = "hacktool_sharpdpapi_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - SharpDPAPI Execution"
  description                = "Detects the execution of the SharpDPAPI tool based on CommandLine flags and PE metadata. SharpDPAPI is a C# port of some DPAPI functionality from the Mimikatz project."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\SharpDPAPI.exe" or ProcessVersionInfoOriginalFileName =~ "SharpDPAPI.exe") or ((ProcessCommandLine contains " backupkey " or ProcessCommandLine contains " blob " or ProcessCommandLine contains " certificates " or ProcessCommandLine contains " credentials " or ProcessCommandLine contains " keepass " or ProcessCommandLine contains " masterkeys " or ProcessCommandLine contains " rdg " or ProcessCommandLine contains " vaults ") and ((ProcessCommandLine contains " /file:" or ProcessCommandLine contains " /machine" or ProcessCommandLine contains " /mkfile:" or ProcessCommandLine contains " /password:" or ProcessCommandLine contains " /pvk:" or ProcessCommandLine contains " /server:" or ProcessCommandLine contains " /target:" or ProcessCommandLine contains " /unprotect") or (ProcessCommandLine contains " {" and ProcessCommandLine contains "}:")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion"]
  techniques                 = ["T1134"]
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