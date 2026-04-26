resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_hktl_netexec" {
  name                       = "proc_creation_win_hktl_netexec"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - NetExec Execution"
  description                = <<DESC
    Detects execution of the hacktool NetExec. NetExec (formerly CrackMapExec) is a widely used post-exploitation tool designed for Active Directory penetration testing and network enumeration In enterprise environments, the use of NetExec is considered suspicious or potentially malicious because it enables attackers to enumerate hosts, exploit network services, and move laterally across systems. Threat actors and red teams commonly use NetExec to identify vulnerable systems, harvest credentials, and execute commands remotely.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_netexec.yml

    False Positives:
    - Legitimate use of NetExec by security professionals or system administrators for network assessment and management.
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " ftp " or ProcessCommandLine contains " ldap " or ProcessCommandLine contains " mssql " or ProcessCommandLine contains " nfs " or ProcessCommandLine contains " rdp " or ProcessCommandLine contains " smb " or ProcessCommandLine contains " ssh " or ProcessCommandLine contains " vnc " or ProcessCommandLine contains " winrm " or ProcessCommandLine contains " wmi ") and FolderPath endswith "\\nxc.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery", "LateralMovement"]
  techniques                 = ["T1018", "T1021"]
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}