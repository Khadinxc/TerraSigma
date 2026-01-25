resource "azurerm_sentinel_alert_rule_scheduled" "pua_kernel_driver_utility_kdu_execution" {
  name                       = "pua_kernel_driver_utility_kdu_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - Kernel Driver Utility (KDU) Execution"
  description                = "Detects execution of the Kernel Driver Utility (KDU) tool. KDU can be used to bypass driver signature enforcement and load unsigned or malicious drivers into the Windows kernel. Potentially allowing for privilege escalation, persistence, or evasion of security controls. - Legitimate driver development, testing, or administrative troubleshooting (e.g., enabling/disabling hardware)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-map " or ProcessCommandLine contains "-prv " or ProcessCommandLine contains "-dse " or ProcessCommandLine contains "-ps ") and ((FolderPath endswith "\\kdu.exe" or FolderPath endswith "\\hamakaze.exe") or ProcessVersionInfoOriginalFileName =~ "hamakaze.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1543"]
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