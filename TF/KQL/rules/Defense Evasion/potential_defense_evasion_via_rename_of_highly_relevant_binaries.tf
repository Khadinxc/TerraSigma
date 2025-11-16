resource "azurerm_sentinel_alert_rule_scheduled" "potential_defense_evasion_via_rename_of_highly_relevant_binaries" {
  name                       = "potential_defense_evasion_via_rename_of_highly_relevant_binaries"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Defense Evasion Via Rename Of Highly Relevant Binaries"
  description                = "Detects the execution of a renamed binary often used by attackers or malware leveraging new Sysmon OriginalFileName datapoint. - Custom applications use renamed binaries adding slight change to binary name. Typically this is easy to spot and add to whitelist"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessVersionInfoFileDescription =~ "Execute processes remotely" or ProcessVersionInfoProductName =~ "Sysinternals PsExec" or (ProcessVersionInfoFileDescription startswith "Windows PowerShell" or ProcessVersionInfoFileDescription startswith "pwsh") or (ProcessVersionInfoOriginalFileName in~ ("certutil.exe", "cmstp.exe", "cscript.exe", "IE4UINIT.EXE", "mshta.exe", "msiexec.exe", "msxsl.exe", "powershell_ise.exe", "powershell.exe", "psexec.c", "psexec.exe", "psexesvc.exe", "pwsh.dll", "reg.exe", "regsvr32.exe", "rundll32.exe", "WerMgr", "wmic.exe", "wscript.exe"))) and (not((FolderPath endswith "\\certutil.exe" or FolderPath endswith "\\cmstp.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\ie4uinit.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\msiexec.exe" or FolderPath endswith "\\msxsl.exe" or FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\psexec.exe" or FolderPath endswith "\\psexec64.exe" or FolderPath endswith "\\PSEXESVC.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\reg.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\wermgr.exe" or FolderPath endswith "\\wmic.exe" or FolderPath endswith "\\wscript.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036"]
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
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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