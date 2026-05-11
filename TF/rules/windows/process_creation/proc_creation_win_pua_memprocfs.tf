resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_pua_memprocfs" {
  name                       = "proc_creation_win_pua_memprocfs"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - Memory Dump Mount Via MemProcFS"
  description                = <<DESC
    Detects execution of MemProcFS a memory forensics tool with the '-device' parameter. MemProcFS mounts physical memory as a virtual file system, allowing direct access to process memory and system structures. Threat actors were seen abusing this utility to mount memory dumps and then extract sensitive information from processes like LSASS or extract registry hives to obtain credentials, LSA secrets, SAM data, and cached domain credentials. MemProcFS usage that is not part of authorized forensic analysis should be treated as suspicious and warrants further investigation.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_pua_memprocfs.yml

    False Positives:
    - Legitimate use during memory forensics; if not part of authorized analysis, warrants urgent investigation
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "-device" and (FolderPath endswith "\\MemProcFS.exe" or ProcessVersionInfoOriginalFileName =~ "MemProcFS.exe" or ProcessVersionInfoFileDescription =~ "MemProcFS")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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