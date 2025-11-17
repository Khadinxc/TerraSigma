resource "azurerm_sentinel_alert_rule_scheduled" "abuse_of_service_permissions_to_hide_services_via_set_service" {
  name                       = "abuse_of_service_permissions_to_hide_services_via_set_service"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Abuse of Service Permissions to Hide Services Via Set-Service"
  description                = "Detects usage of the \"Set-Service\" powershell cmdlet to configure a new SecurityDescriptor that allows a service to be hidden from other utilities such as \"sc.exe\", \"Get-Service\"...etc. (Works only in powershell 7) - Rare intended use of hidden services"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-SecurityDescriptorSddl " or ProcessCommandLine contains "-sd ") and (FolderPath endswith "\\pwsh.exe" or ProcessVersionInfoOriginalFileName =~ "pwsh.dll") and (ProcessCommandLine contains "Set-Service " and ProcessCommandLine contains "DCLCWPDTSD")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1574"]
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