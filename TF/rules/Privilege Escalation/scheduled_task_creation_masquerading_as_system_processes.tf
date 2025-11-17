resource "azurerm_sentinel_alert_rule_scheduled" "scheduled_task_creation_masquerading_as_system_processes" {
  name                       = "scheduled_task_creation_masquerading_as_system_processes"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Scheduled Task Creation Masquerading as System Processes"
  description                = "Detects the creation of scheduled tasks that involve system processes, which may indicate malicious actors masquerading as or abusing these processes to execute payloads or maintain persistence. - Legitimate system administration tasks scheduling trusted system processes."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " audiodg" or ProcessCommandLine contains " conhost" or ProcessCommandLine contains " dwm.exe" or ProcessCommandLine contains " explorer" or ProcessCommandLine contains " lsass" or ProcessCommandLine contains " lsm" or ProcessCommandLine contains " mmc" or ProcessCommandLine contains " msiexec" or ProcessCommandLine contains " regsvr32" or ProcessCommandLine contains " rundll32" or ProcessCommandLine contains " services" or ProcessCommandLine contains " spoolsv" or ProcessCommandLine contains " svchost" or ProcessCommandLine contains " taskeng" or ProcessCommandLine contains " taskhost" or ProcessCommandLine contains " wininit" or ProcessCommandLine contains " winlogon") and (ProcessCommandLine contains " -create " or ProcessCommandLine contains " /create " or ProcessCommandLine contains " –create " or ProcessCommandLine contains " —create " or ProcessCommandLine contains " ―create ")) and (FolderPath endswith "\\schtasks.exe" or ProcessVersionInfoOriginalFileName =~ "schtasks.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Execution", "Persistence", "DefenseEvasion"]
  techniques                 = ["T1053", "T1036"]
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