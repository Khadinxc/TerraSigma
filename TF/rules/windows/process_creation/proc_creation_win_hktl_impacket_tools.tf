resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_hktl_impacket_tools" {
  name                       = "proc_creation_win_hktl_impacket_tools"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - Impacket Tools Execution"
  description                = <<DESC
    Detects the execution of different compiled Windows binaries of the impacket toolset (based on names or part of their names - could lead to false positives)

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_impacket_tools.yml

    False Positives:
    - Legitimate use of the impacket tools
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath contains "\\goldenPac" or FolderPath contains "\\karmaSMB" or FolderPath contains "\\kintercept" or FolderPath contains "\\ntlmrelayx" or FolderPath contains "\\rpcdump" or FolderPath contains "\\samrdump" or FolderPath contains "\\secretsdump" or FolderPath contains "\\smbexec" or FolderPath contains "\\smbrelayx" or FolderPath contains "\\wmiexec" or FolderPath contains "\\wmipersist") or (FolderPath endswith "\\atexec_windows.exe" or FolderPath endswith "\\dcomexec_windows.exe" or FolderPath endswith "\\dpapi_windows.exe" or FolderPath endswith "\\findDelegation_windows.exe" or FolderPath endswith "\\GetADUsers_windows.exe" or FolderPath endswith "\\GetNPUsers_windows.exe" or FolderPath endswith "\\getPac_windows.exe" or FolderPath endswith "\\getST_windows.exe" or FolderPath endswith "\\getTGT_windows.exe" or FolderPath endswith "\\GetUserSPNs_windows.exe" or FolderPath endswith "\\ifmap_windows.exe" or FolderPath endswith "\\mimikatz_windows.exe" or FolderPath endswith "\\netview_windows.exe" or FolderPath endswith "\\nmapAnswerMachine_windows.exe" or FolderPath endswith "\\opdump_windows.exe" or FolderPath endswith "\\psexec_windows.exe" or FolderPath endswith "\\rdp_check_windows.exe" or FolderPath endswith "\\sambaPipe_windows.exe" or FolderPath endswith "\\smbclient_windows.exe" or FolderPath endswith "\\smbserver_windows.exe" or FolderPath endswith "\\sniff_windows.exe" or FolderPath endswith "\\sniffer_windows.exe" or FolderPath endswith "\\split_windows.exe" or FolderPath endswith "\\ticketer_windows.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection", "Execution", "CredentialAccess"]
  techniques                 = ["T1557"]
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
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}