resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_shellexec_rundll_call_via_ordinal" {
  name                       = "suspicious_shellexec_rundll_call_via_ordinal"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious ShellExec_RunDLL Call Via Ordinal"
  description                = "Detects suspicious call to the \"ShellExec_RunDLL\" exported function of SHELL32.DLL through the ordinal number to launch other commands. Adversary might only use the ordinal number in order to bypass existing detection that alert on usage of ShellExec_RunDLL on CommandLine."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (InitiatingProcessCommandLine contains "SHELL32.DLL" and (InitiatingProcessCommandLine contains "#568" or InitiatingProcessCommandLine contains "#570" or InitiatingProcessCommandLine contains "#572" or InitiatingProcessCommandLine contains "#576")) and ((FolderPath endswith "\\bash.exe" or FolderPath endswith "\\bitsadmin.exe" or FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\curl.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\msiexec.exe" or FolderPath endswith "\\msxsl.exe" or FolderPath endswith "\\odbcconf.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\schtasks.exe" or FolderPath endswith "\\wmic.exe" or FolderPath endswith "\\wscript.exe") or ((InitiatingProcessCommandLine contains "comspec" or InitiatingProcessCommandLine contains "iex" or InitiatingProcessCommandLine contains "Invoke-" or InitiatingProcessCommandLine contains "msiexec" or InitiatingProcessCommandLine contains "odbcconf" or InitiatingProcessCommandLine contains "regsvr32") or (InitiatingProcessCommandLine contains "\\Desktop\\" or InitiatingProcessCommandLine contains "\\ProgramData\\" or InitiatingProcessCommandLine contains "\\Temp\\" or InitiatingProcessCommandLine contains "\\Users\\Public\\")))
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