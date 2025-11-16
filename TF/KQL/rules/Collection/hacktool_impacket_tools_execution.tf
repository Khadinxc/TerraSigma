resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_impacket_tools_execution" {
  name                       = "hacktool_impacket_tools_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - Impacket Tools Execution"
  description                = "Detects the execution of different compiled Windows binaries of the impacket toolset (based on names or part of their names - could lead to false positives) - Legitimate use of the impacket tools"
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
    entity_type = "Process"
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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