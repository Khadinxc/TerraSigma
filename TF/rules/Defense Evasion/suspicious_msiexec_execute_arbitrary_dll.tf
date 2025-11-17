resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_msiexec_execute_arbitrary_dll" {
  name                       = "suspicious_msiexec_execute_arbitrary_dll"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Msiexec Execute Arbitrary DLL"
  description                = "Adversaries may abuse msiexec.exe to proxy execution of malicious payloads. Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi) - Legitimate script"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " -y" or ProcessCommandLine contains " /y" or ProcessCommandLine contains " –y" or ProcessCommandLine contains " —y" or ProcessCommandLine contains " ―y") and FolderPath endswith "\\msiexec.exe") and (not((ProcessCommandLine contains "\\MsiExec.exe\" /Y \"C:\\Program Files\\Bonjour\\mdnsNSP.dll" or ProcessCommandLine contains "\\MsiExec.exe\" /Y \"C:\\Program Files (x86)\\Bonjour\\mdnsNSP.dll" or ProcessCommandLine contains "\\MsiExec.exe\" /Y \"C:\\Program Files (x86)\\Apple Software Update\\ScriptingObjectModel.dll" or ProcessCommandLine contains "\\MsiExec.exe\" /Y \"C:\\Program Files (x86)\\Apple Software Update\\SoftwareUpdateAdmin.dll" or ProcessCommandLine contains "\\MsiExec.exe\" /Y \"C:\\Windows\\CCM\\" or ProcessCommandLine contains "\\MsiExec.exe\" /Y C:\\Windows\\CCM\\" or ProcessCommandLine contains "\\MsiExec.exe\" -Y \"C:\\Program Files\\Bonjour\\mdnsNSP.dll" or ProcessCommandLine contains "\\MsiExec.exe\" -Y \"C:\\Program Files (x86)\\Bonjour\\mdnsNSP.dll" or ProcessCommandLine contains "\\MsiExec.exe\" -Y \"C:\\Program Files (x86)\\Apple Software Update\\ScriptingObjectModel.dll" or ProcessCommandLine contains "\\MsiExec.exe\" -Y \"C:\\Program Files (x86)\\Apple Software Update\\SoftwareUpdateAdmin.dll" or ProcessCommandLine contains "\\MsiExec.exe\" -Y \"C:\\Windows\\CCM\\" or ProcessCommandLine contains "\\MsiExec.exe\" -Y C:\\Windows\\CCM\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}