resource "azurerm_sentinel_alert_rule_scheduled" "hktl_sharpsuccessor_privilege_escalation_tool_execution" {
  name                       = "hktl_sharpsuccessor_privilege_escalation_tool_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HKTL - SharpSuccessor Privilege Escalation Tool Execution"
  description                = "Detects the execution of SharpSuccessor, a tool used to exploit the BadSuccessor attack for privilege escalation in WinServer 2025 Active Directory environments. Successful usage of this tool can let the attackers gain the domain admin privileges by exploiting the BadSuccessor vulnerability."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\SharpSuccessor.exe" or ProcessVersionInfoOriginalFileName =~ "SharpSuccessor.exe" or ProcessCommandLine contains "SharpSuccessor" or (ProcessCommandLine contains " add " and ProcessCommandLine contains " /impersonate" and ProcessCommandLine contains " /path" and ProcessCommandLine contains " /account" and ProcessCommandLine contains " /name")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation"]
  techniques                 = ["T1068"]
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