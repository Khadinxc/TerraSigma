resource "azurerm_sentinel_alert_rule_scheduled" "hypervisor_protected_code_integrity_hvci_related_registry_tampering_via_commandline" {
  name                       = "hypervisor_protected_code_integrity_hvci_related_registry_tampering_via_commandline"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Hypervisor-protected Code Integrity (HVCI) Related Registry Tampering Via CommandLine"
  description                = "Detects the tampering of Hypervisor-protected Code Integrity (HVCI) related registry values via command line tool reg.exe. HVCI uses virtualization-based security to protect code integrity by ensuring that only trusted code can run in kernel mode. Adversaries may tamper with HVCI to load malicious or unsigned drivers, which can be used to escalate privileges, maintain persistence, or evade security mechanisms. - Legitimate system administration tasks that require disabling HVCI for troubleshooting purposes when certain drivers or applications are incompatible with it."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "add " or ProcessCommandLine contains "New-ItemProperty " or ProcessCommandLine contains "Set-ItemProperty " or ProcessCommandLine contains "si ") and ProcessCommandLine contains "\\DeviceGuard" and (ProcessCommandLine contains "EnableVirtualizationBasedSecurity" or ProcessCommandLine contains "HypervisorEnforcedCodeIntegrity") and ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\reg.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll", "reg.exe")))
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