resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_microsoft_office_child_process" {
  name                       = "suspicious_microsoft_office_child_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Microsoft Office Child Process"
  description                = "Detects a suspicious process spawning from one of the Microsoft Office suite products (Word, Excel, PowerPoint, Publisher, Visio, etc.)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (InitiatingProcessFolderPath endswith "\\EQNEDT32.EXE" or InitiatingProcessFolderPath endswith "\\EXCEL.EXE" or InitiatingProcessFolderPath endswith "\\MSACCESS.EXE" or InitiatingProcessFolderPath endswith "\\MSPUB.exe" or InitiatingProcessFolderPath endswith "\\ONENOTE.EXE" or InitiatingProcessFolderPath endswith "\\POWERPNT.exe" or InitiatingProcessFolderPath endswith "\\VISIO.exe" or InitiatingProcessFolderPath endswith "\\WINWORD.EXE" or InitiatingProcessFolderPath endswith "\\wordpad.exe" or InitiatingProcessFolderPath endswith "\\wordview.exe") and (((ProcessVersionInfoOriginalFileName in~ ("bitsadmin.exe", "CertOC.exe", "CertUtil.exe", "Cmd.Exe", "CMSTP.EXE", "cscript.exe", "curl.exe", "HH.exe", "IEExec.exe", "InstallUtil.exe", "javaw.exe", "Microsoft.Workflow.Compiler.exe", "msdt.exe", "MSHTA.EXE", "msiexec.exe", "Msxsl.exe", "odbcconf.exe", "pcalua.exe", "PowerShell.EXE", "RegAsm.exe", "RegSvcs.exe", "REGSVR32.exe", "RUNDLL32.exe", "schtasks.exe", "ScriptRunner.exe", "wmic.exe", "WorkFolders.exe", "wscript.exe")) or (FolderPath endswith "\\AppVLP.exe" or FolderPath endswith "\\bash.exe" or FolderPath endswith "\\bitsadmin.exe" or FolderPath endswith "\\certoc.exe" or FolderPath endswith "\\certutil.exe" or FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\cmstp.exe" or FolderPath endswith "\\control.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\curl.exe" or FolderPath endswith "\\forfiles.exe" or FolderPath endswith "\\hh.exe" or FolderPath endswith "\\ieexec.exe" or FolderPath endswith "\\installutil.exe" or FolderPath endswith "\\javaw.exe" or FolderPath endswith "\\mftrace.exe" or FolderPath endswith "\\Microsoft.Workflow.Compiler.exe" or FolderPath endswith "\\msbuild.exe" or FolderPath endswith "\\msdt.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\msidb.exe" or FolderPath endswith "\\msiexec.exe" or FolderPath endswith "\\msxsl.exe" or FolderPath endswith "\\odbcconf.exe" or FolderPath endswith "\\pcalua.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\regasm.exe" or FolderPath endswith "\\regsvcs.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\schtasks.exe" or FolderPath endswith "\\scrcons.exe" or FolderPath endswith "\\scriptrunner.exe" or FolderPath endswith "\\sh.exe" or FolderPath endswith "\\svchost.exe" or FolderPath endswith "\\verclsid.exe" or FolderPath endswith "\\wmic.exe" or FolderPath endswith "\\workfolders.exe" or FolderPath endswith "\\wscript.exe")) or (FolderPath contains "\\AppData\\" or FolderPath contains "\\Users\\Public\\" or FolderPath contains "\\ProgramData\\" or FolderPath contains "\\Windows\\Tasks\\" or FolderPath contains "\\Windows\\Temp\\" or FolderPath contains "\\Windows\\System32\\Tasks\\"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
  techniques                 = ["T1047", "T1204", "T1218"]
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