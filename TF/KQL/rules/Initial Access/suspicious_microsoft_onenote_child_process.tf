resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_microsoft_onenote_child_process" {
  name                       = "suspicious_microsoft_onenote_child_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Microsoft OneNote Child Process"
  description                = "Detects suspicious child processes of the Microsoft OneNote application. This may indicate an attempt to execute malicious embedded objects from a .one file. - File located in the AppData folder with trusted signature"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\onenote.exe" and (((ProcessCommandLine contains ".hta" or ProcessCommandLine contains ".vb" or ProcessCommandLine contains ".wsh" or ProcessCommandLine contains ".js" or ProcessCommandLine contains ".ps" or ProcessCommandLine contains ".scr" or ProcessCommandLine contains ".pif" or ProcessCommandLine contains ".bat" or ProcessCommandLine contains ".cmd") and FolderPath endswith "\\explorer.exe") or ((ProcessVersionInfoOriginalFileName in~ ("bitsadmin.exe", "CertOC.exe", "CertUtil.exe", "Cmd.Exe", "CMSTP.EXE", "cscript.exe", "curl.exe", "HH.exe", "IEExec.exe", "InstallUtil.exe", "javaw.exe", "Microsoft.Workflow.Compiler.exe", "msdt.exe", "MSHTA.EXE", "msiexec.exe", "Msxsl.exe", "odbcconf.exe", "pcalua.exe", "PowerShell.EXE", "RegAsm.exe", "RegSvcs.exe", "REGSVR32.exe", "RUNDLL32.exe", "schtasks.exe", "ScriptRunner.exe", "wmic.exe", "WorkFolders.exe", "wscript.exe")) or (FolderPath endswith "\\AppVLP.exe" or FolderPath endswith "\\bash.exe" or FolderPath endswith "\\bitsadmin.exe" or FolderPath endswith "\\certoc.exe" or FolderPath endswith "\\certutil.exe" or FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\cmstp.exe" or FolderPath endswith "\\control.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\curl.exe" or FolderPath endswith "\\forfiles.exe" or FolderPath endswith "\\hh.exe" or FolderPath endswith "\\ieexec.exe" or FolderPath endswith "\\installutil.exe" or FolderPath endswith "\\javaw.exe" or FolderPath endswith "\\mftrace.exe" or FolderPath endswith "\\Microsoft.Workflow.Compiler.exe" or FolderPath endswith "\\msbuild.exe" or FolderPath endswith "\\msdt.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\msidb.exe" or FolderPath endswith "\\msiexec.exe" or FolderPath endswith "\\msxsl.exe" or FolderPath endswith "\\odbcconf.exe" or FolderPath endswith "\\pcalua.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\regasm.exe" or FolderPath endswith "\\regsvcs.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\schtasks.exe" or FolderPath endswith "\\scrcons.exe" or FolderPath endswith "\\scriptrunner.exe" or FolderPath endswith "\\sh.exe" or FolderPath endswith "\\svchost.exe" or FolderPath endswith "\\verclsid.exe" or FolderPath endswith "\\wmic.exe" or FolderPath endswith "\\workfolders.exe" or FolderPath endswith "\\wscript.exe")) or (FolderPath contains "\\AppData\\" or FolderPath contains "\\Users\\Public\\" or FolderPath contains "\\ProgramData\\" or FolderPath contains "\\Windows\\Tasks\\" or FolderPath contains "\\Windows\\Temp\\" or FolderPath contains "\\Windows\\System32\\Tasks\\")) and (not(((ProcessCommandLine endswith "-Embedding" and FolderPath contains "\\AppData\\Local\\Microsoft\\OneDrive\\" and FolderPath endswith "\\FileCoAuth.exe") or (ProcessCommandLine endswith "-Embedding" and FolderPath endswith "\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess"]
  techniques                 = ["T1566"]
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
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
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