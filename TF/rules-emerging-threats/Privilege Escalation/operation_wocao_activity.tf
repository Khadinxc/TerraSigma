resource "azurerm_sentinel_alert_rule_scheduled" "operation_wocao_activity" {
  name                       = "operation_wocao_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Operation Wocao Activity"
  description                = "Detects activity mentioned in Operation Wocao report - Administrators that use checkadmin.exe tool to enumerate local administrators"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "checkadmin.exe 127.0.0.1 -all" or ProcessCommandLine contains "netsh advfirewall firewall add rule name=powershell dir=in" or ProcessCommandLine contains "cmd /c powershell.exe -ep bypass -file c:\\s.ps1" or ProcessCommandLine contains "/tn win32times /f" or ProcessCommandLine contains "create win32times binPath=" or ProcessCommandLine contains "\\c$\\windows\\system32\\devmgr.dll" or ProcessCommandLine contains " -exec bypass -enc JgAg" or (ProcessCommandLine contains "type " and ProcessCommandLine contains "keepass\\KeePass.config.xml") or ProcessCommandLine contains "iie.exe iie.txt" or (ProcessCommandLine contains "reg query HKEY_CURRENT_USER\\Software\\" and ProcessCommandLine contains "\\PuTTY\\Sessions\\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "Discovery", "DefenseEvasion", "Execution"]
  techniques                 = ["T1012", "T1036", "T1027", "T1053", "T1059"]
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
}