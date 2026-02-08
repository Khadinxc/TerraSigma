resource "azurerm_sentinel_alert_rule_scheduled" "windows_credential_guard_registry_tampering_via_commandline" {
  name                       = "windows_credential_guard_registry_tampering_via_commandline"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Windows Credential Guard Registry Tampering Via CommandLine"
  description                = "Detects attempts to add, modify, or delete Windows Credential Guard related registry keys or values via command line tools such as Reg.exe or PowerShell. Credential Guard uses virtualization-based security to isolate secrets so that only privileged system software can access them. Adversaries may disable Credential Guard to gain access to sensitive credentials stored in the system, such as NTLM hashes and Kerberos tickets, which can be used for lateral movement and privilege escalation. The rule matches suspicious command lines that target DeviceGuard or LSA registry paths and manipulate keys like EnableVirtualizationBasedSecurity, RequirePlatformSecurityFeatures, or LsaCfgFlags. Such activity may indicate an attempt to disable or tamper with Credential Guard, potentially exposing sensitive credentials for misuse. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "add " or ProcessCommandLine contains "New-ItemProperty " or ProcessCommandLine contains "Set-ItemProperty " or ProcessCommandLine contains "si " or ProcessCommandLine contains "delete " or ProcessCommandLine contains "del " or ProcessCommandLine contains "Remove-ItemProperty " or ProcessCommandLine contains "rp ") and ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\reg.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll", "reg.exe"))) and (ProcessCommandLine contains "\\Control\\DeviceGuard" or ProcessCommandLine contains "\\Control\\LSA" or ProcessCommandLine contains "Software\\Policies\\Microsoft\\Windows\\DeviceGuard") and (ProcessCommandLine contains "EnableVirtualizationBasedSecurity" or ProcessCommandLine contains "RequirePlatformSecurityFeatures" or ProcessCommandLine contains "LsaCfgFlags")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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