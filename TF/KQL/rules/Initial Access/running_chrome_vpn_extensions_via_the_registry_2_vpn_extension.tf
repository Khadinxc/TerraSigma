resource "azurerm_sentinel_alert_rule_scheduled" "running_chrome_vpn_extensions_via_the_registry_2_vpn_extension" {
  name                       = "running_chrome_vpn_extensions_via_the_registry_2_vpn_extension"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Running Chrome VPN Extensions via the Registry 2 VPN Extension"
  description                = "Running Chrome VPN Extensions via the Registry install 2 vpn extension"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey contains "Software\\Wow6432Node\\Google\\Chrome\\Extensions" and RegistryKey endswith "update_url") and (RegistryKey contains "fdcgdnkidjaadafnichfpabhfomcebme" or RegistryKey contains "fcfhplploccackoneaefokcmbjfbkenj" or RegistryKey contains "bihmplhobchoageeokmgbdihknkjbknd" or RegistryKey contains "gkojfkhlekighikafcpjkiklfbnlmeio" or RegistryKey contains "jajilbjjinjmgcibalaakngmkilboobh" or RegistryKey contains "gjknjjomckknofjidppipffbpoekiipm" or RegistryKey contains "nabbmpekekjknlbkgpodfndbodhijjem" or RegistryKey contains "kpiecbcckbofpmkkkdibbllpinceiihk" or RegistryKey contains "nlbejmccbhkncgokjcmghpfloaajcffj" or RegistryKey contains "omghfjlpggmjjaagoclmmobgdodcjboh" or RegistryKey contains "bibjcjfmgapbfoljiojpipaooddpkpai" or RegistryKey contains "mpcaainmfjjigeicjnlkdfajbioopjko" or RegistryKey contains "jljopmgdobloagejpohpldgkiellmfnc" or RegistryKey contains "lochiccbgeohimldjooaakjllnafhaid" or RegistryKey contains "nhnfcgpcbfclhfafjlooihdfghaeinfc" or RegistryKey contains "ookhnhpkphagefgdiemllfajmkdkcaim" or RegistryKey contains "namfblliamklmeodpcelkokjbffgmeoo" or RegistryKey contains "nbcojefnccbanplpoffopkoepjmhgdgh" or RegistryKey contains "majdfhpaihoncoakbjgbdhglocklcgno" or RegistryKey contains "lnfdmdhmfbimhhpaeocncdlhiodoblbd" or RegistryKey contains "eppiocemhmnlbhjplcgkofciiegomcon" or RegistryKey contains "cocfojppfigjeefejbpfmedgjbpchcng" or RegistryKey contains "foiopecknacmiihiocgdjgbjokkpkohc" or RegistryKey contains "hhdobjgopfphlmjbmnpglhfcgppchgje" or RegistryKey contains "jgbaghohigdbgbolncodkdlpenhcmcge" or RegistryKey contains "inligpkjkhbpifecbdjhmdpcfhnlelja" or RegistryKey contains "higioemojdadgdbhbbbkfbebbdlfjbip" or RegistryKey contains "hipncndjamdcmphkgngojegjblibadbe" or RegistryKey contains "iolonopooapdagdemdoaihahlfkncfgg" or RegistryKey contains "nhfjkakglbnnpkpldhjmpmmfefifedcj" or RegistryKey contains "jpgljfpmoofbmlieejglhonfofmahini" or RegistryKey contains "fgddmllnllkalaagkghckoinaemmogpe" or RegistryKey contains "ejkaocphofnobjdedneohbbiilggdlbi" or RegistryKey contains "keodbianoliadkoelloecbhllnpiocoi" or RegistryKey contains "hoapmlpnmpaehilehggglehfdlnoegck" or RegistryKey contains "poeojclicodamonabcabmapamjkkmnnk" or RegistryKey contains "dfkdflfgjdajbhocmfjolpjbebdkcjog" or RegistryKey contains "kcdahmgmaagjhocpipbodaokikjkampi" or RegistryKey contains "klnkiajpmpkkkgpgbogmcgfjhdoljacg" or RegistryKey contains "lneaocagcijjdpkcabeanfpdbmapcjjg" or RegistryKey contains "pgfpignfckbloagkfnamnolkeaecfgfh" or RegistryKey contains "jplnlifepflhkbkgonidnobkakhmpnmh" or RegistryKey contains "jliodmnojccaloajphkingdnpljdhdok" or RegistryKey contains "hnmpcagpplmpfojmgmnngilcnanddlhb" or RegistryKey contains "ffbkglfijbcbgblgflchnbphjdllaogb" or RegistryKey contains "kcndmbbelllkmioekdagahekgimemejo" or RegistryKey contains "jdgilggpfmjpbodmhndmhojklgfdlhob" or RegistryKey contains "bihhflimonbpcfagfadcnbbdngpopnjb" or RegistryKey contains "ppajinakbfocjfnijggfndbdmjggcmde" or RegistryKey contains "oofgbpoabipfcfjapgnbbjjaenockbdp" or RegistryKey contains "bhnhkdgoefpmekcgnccpnhjfdgicfebm" or RegistryKey contains "knmmpciebaoojcpjjoeonlcjacjopcpf" or RegistryKey contains "dhadilbmmjiooceioladdphemaliiobo" or RegistryKey contains "jedieiamjmoflcknjdjhpieklepfglin" or RegistryKey contains "mhngpdlhojliikfknhfaglpnddniijfh" or RegistryKey contains "omdakjcmkglenbhjadbccaookpfjihpa" or RegistryKey contains "npgimkapccfidfkfoklhpkgmhgfejhbj" or RegistryKey contains "akeehkgglkmpapdnanoochpfmeghfdln" or RegistryKey contains "gbmdmipapolaohpinhblmcnpmmlgfgje" or RegistryKey contains "aigmfoeogfnljhnofglledbhhfegannp" or RegistryKey contains "cgojmfochfikphincbhokimmmjenhhgk" or RegistryKey contains "ficajfeojakddincjafebjmfiefcmanc" or RegistryKey contains "ifnaibldjfdmaipaddffmgcmekjhiloa" or RegistryKey contains "jbnmpdkcfkochpanomnkhnafobppmccn" or RegistryKey contains "apcfdffemoinopelidncddjbhkiblecc" or RegistryKey contains "mjolnodfokkkaichkcjipfgblbfgojpa" or RegistryKey contains "oifjbnnafapeiknapihcmpeodaeblbkn" or RegistryKey contains "plpmggfglncceinmilojdkiijhmajkjh" or RegistryKey contains "mjnbclmflcpookeapghfhapeffmpodij" or RegistryKey contains "bblcccknbdbplgmdjnnikffefhdlobhp" or RegistryKey contains "aojlhgbkmkahabcmcpifbolnoichfeep" or RegistryKey contains "lcmammnjlbmlbcaniggmlejfjpjagiia" or RegistryKey contains "knajdeaocbpmfghhmijicidfcmdgbdpm" or RegistryKey contains "bdlcnpceagnkjnjlbbbcepohejbheilk" or RegistryKey contains "edknjdjielmpdlnllkdmaghlbpnmjmgb" or RegistryKey contains "eidnihaadmmancegllknfbliaijfmkgo" or RegistryKey contains "ckiahbcmlmkpfiijecbpflfahoimklke" or RegistryKey contains "macdlemfnignjhclfcfichcdhiomgjjb" or RegistryKey contains "chioafkonnhbpajpengbalkececleldf" or RegistryKey contains "amnoibeflfphhplmckdbiajkjaoomgnj" or RegistryKey contains "llbhddikeonkpbhpncnhialfbpnilcnc" or RegistryKey contains "pcienlhnoficegnepejpfiklggkioccm" or RegistryKey contains "iocnglnmfkgfedpcemdflhkchokkfeii" or RegistryKey contains "igahhbkcppaollcjeaaoapkijbnphfhb" or RegistryKey contains "njpmifchgidinihmijhcfpbdmglecdlb" or RegistryKey contains "ggackgngljinccllcmbgnpgpllcjepgc" or RegistryKey contains "kchocjcihdgkoplngjemhpplmmloanja" or RegistryKey contains "bnijmipndnicefcdbhgcjoognndbgkep" or RegistryKey contains "lklekjodgannjcccdlbicoamibgbdnmi" or RegistryKey contains "dbdbnchagbkhknegmhgikkleoogjcfge" or RegistryKey contains "egblhcjfjmbjajhjhpmnlekffgaemgfh" or RegistryKey contains "ehbhfpfdkmhcpaehaooegfdflljcnfec" or RegistryKey contains "bkkgdjpomdnfemhhkalfkogckjdkcjkg" or RegistryKey contains "almalgbpmcfpdaopimbdchdliminoign" or RegistryKey contains "akkbkhnikoeojlhiiomohpdnkhbkhieh" or RegistryKey contains "gbfgfbopcfokdpkdigfmoeaajfmpkbnh" or RegistryKey contains "bniikohfmajhdcffljgfeiklcbgffppl" or RegistryKey contains "lejgfmmlngaigdmmikblappdafcmkndb" or RegistryKey contains "ffhhkmlgedgcliajaedapkdfigdobcif" or RegistryKey contains "gcknhkkoolaabfmlnjonogaaifnjlfnp" or RegistryKey contains "pooljnboifbodgifngpppfklhifechoe" or RegistryKey contains "fjoaledfpmneenckfbpdfhkmimnjocfa" or RegistryKey contains "aakchaleigkohafkfjfjbblobjifikek" or RegistryKey contains "dpplabbmogkhghncfbfdeeokoefdjegm" or RegistryKey contains "padekgcemlokbadohgkifijomclgjgif" or RegistryKey contains "bfidboloedlamgdmenmlbipfnccokknp")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess", "Persistence"]
  techniques                 = ["T1133"]
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
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }
}