using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;
using System.Threading;
using System.Net.NetworkInformation;
using System.Net;
using System.Security.Principal;
using System.Text.RegularExpressions;


namespace SharpCheckInfo
{
    class Program
    {
        static void Main(string[] args)
        {

            System.Console.WriteLine("");
            System.Console.WriteLine("Author: Uknow");
            System.Console.WriteLine("Github: https://github.com/uknowsec/SharpCheckInfo");
            System.Console.WriteLine("");
            if (args.Length != 1)
            {
                System.Console.WriteLine("Usage: SharpCheckInfo -All");
                System.Console.WriteLine("       SharpCheckInfo -EnvironmentalVariables");
                System.Console.WriteLine("       SharpCheckInfo -AllUserDirectories");
                System.Console.WriteLine("       SharpCheckInfo -PowershellInfo");
                System.Console.WriteLine("       SharpCheckInfo -CsharpVersion");
                System.Console.WriteLine("       SharpCheckInfo -AvProcessEDRproduct");
                System.Console.WriteLine("       SharpCheckInfo -Defender");
                System.Console.WriteLine("       SharpCheckInfo -RecentFiles");
                System.Console.WriteLine("       SharpCheckInfo -NetworkConnentions");
                System.Console.WriteLine("       SharpCheckInfo -ApplockerEnumerating");
                System.Console.WriteLine("       SharpCheckInfo -Drives");
                System.Console.WriteLine("       SharpCheckInfo -LAPS");
            }
            if (args.Length == 1 && (args[0] == "-All"))
            {
                Console.WriteLine("");
                Console.WriteLine("========== SharpCheckInfo --> All ==========");
                Console.WriteLine("");
                EnvironmentalVariables();
                AllUserDirectories();
                PowershellInfo();
                Csharp_Version();
                AvProcessEDRproduct();
                Defender();
                Recent_files();
                Network_Connentions();
                Applocker_Enumerating();
                Drives();
                LAPS();
            }
            if (args.Length == 1 && (args[0] == "-EnvironmentalVariables"))
            {
                Console.WriteLine("");
                Console.WriteLine("========== SharpCheckInfo --> EnvironmentalVariables ==========");
                Console.WriteLine("");
                EnvironmentalVariables();
            }
            if (args.Length == 1 && (args[0] == "-AllUserDirectories"))
            {
                Console.WriteLine("");
                Console.WriteLine("========== SharpCheckInfo --> AllUserDirectories ==========");
                Console.WriteLine("");
                AllUserDirectories();
            }
            if (args.Length == 1 && (args[0] == "-PowershellInfo"))
            {
                Console.WriteLine("");
                Console.WriteLine("========== SharpCheckInfo --> PowershellInfo ==========");
                Console.WriteLine("");
                PowershellInfo();
            }
            if (args.Length == 1 && (args[0] == "-CsharpVersion"))
            {
                Console.WriteLine("");
                Console.WriteLine("========== SharpCheckInfo --> CsharpVersion ==========");
                Console.WriteLine("");
                Csharp_Version();
            }
            if (args.Length == 1 && (args[0] == "-AvProcessEDRproduct"))
            {
                Console.WriteLine("");
                Console.WriteLine("========== SharpCheckInfo --> AvProcessEDRproduct ==========");
                Console.WriteLine("");
                AvProcessEDRproduct();
            }
            if (args.Length == 1 && (args[0] == "-Defender"))
            {
                Console.WriteLine("");
                Console.WriteLine("========== SharpCheckInfo --> Defender ==========");
                Console.WriteLine("");
                Defender();
            }
            if (args.Length == 1 && (args[0] == "-RecentFiles"))
            {
                Console.WriteLine("");
                Console.WriteLine("========== SharpCheckInfo --> RecentFiles ==========");
                Console.WriteLine("");
                Recent_files();
            }
            if (args.Length == 1 && (args[0] == "-NetworkConnentions"))
            {
                Console.WriteLine("");
                Console.WriteLine("========== SharpCheckInfo --> NetworkConnentions ==========");
                Console.WriteLine("");
                Network_Connentions();
            }
            if (args.Length == 1 && (args[0] == "-ApplockerEnumerating"))
            {
                Console.WriteLine("");
                Console.WriteLine("========== SharpCheckInfo --> ApplockerEnumerating ==========");
                Console.WriteLine("");
                Applocker_Enumerating();
            }
            if (args.Length == 1 && (args[0] == "-Drives"))
            {
                Console.WriteLine("");
                Console.WriteLine("========== SharpCheckInfo --> Drives ==========");
                Console.WriteLine("");
                Drives();
            }
            if (args.Length == 1 && (args[0] == "-LAPS"))
            {
                Console.WriteLine("");
                Console.WriteLine("========== SharpCheckInfo --> LAPS ==========");
                Console.WriteLine("");
                LAPS();
            }
        }

        public static void EnvironmentalVariables()
        {
            //ENVIRONMENTAL VARIABLES  系统信息
            WindowsPrincipal myId = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            var operating_system = Environment.OSVersion;
            Console.WriteLine("[+] Environmental Variables");
            Console.WriteLine("\tComputer Name: " + Environment.MachineName);
            Console.WriteLine("\tPlatform: " + operating_system.Platform + " - " + operating_system.VersionString);
            Console.WriteLine("\tRunning as User: " + Environment.UserName);
            Console.WriteLine("\tLocal Admin Privs: " + myId.IsInRole("BUILTIN\\" + "Administrators"));
            Console.WriteLine("\tOSVersion: {0}", Environment.OSVersion.ToString());
            Console.WriteLine("\tDomain: " + Environment.UserDomainName);
            //获取系统环境变量 用以判断是否安装Java,Python等编程环境
            Console.WriteLine("\n[+] System environment variable Path");
            string path = "Environment";
            RegistryKey masterKey = Registry.CurrentUser.OpenSubKey(path);
            string sPath = masterKey.GetValue("Path").ToString();
            masterKey.Close();
            //string sPath = Environment.GetEnvironmentVariable("Path");
            string[] sArray = Regex.Split(sPath, ";", RegexOptions.IgnoreCase);
            foreach (string i in sArray)
            {
                Console.WriteLine("\t" + i);
            }
        }

        public static void AllUserDirectories()
        {
            //ALL USER FOLDERS ACCESS
            Console.WriteLine("\n[+] All user directories");
            string[] dirs = Directory.GetDirectories(@"c:\users");
            foreach (string dir in dirs)
            {
                try
                {
                    System.Security.AccessControl.DirectorySecurity ds = Directory.GetAccessControl(dir);
                    Console.WriteLine("\t[*] " + dir + " Folder is accessible by current user");
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine("\t[-] " + dir + " Folder is NOT accessible by current user");
                }
            }
        }

        public static void PowershellInfo()
        {
            //CHECK FOR REGISTRY x64/x32   检查注册表
            var registryKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            RegistryKey key = registryKey.OpenSubKey("Software");
            if (key == null)
            {
                registryKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
            }
            //POWERSHELL VERSIONS       powershell版本
            Console.WriteLine("\n[+] PowerShell Versions Installed");
            string[] directories = Directory.GetDirectories(@"C:\windows\System32\WindowsPowershell");
            for (int i = 0; i < directories.Length; i++)
            {
                Console.WriteLine("\t" + directories[i]);
            }
            //POWERSHELL HISTORY FILE    powershell 历史记录
            Console.WriteLine("\n[+] Checking for PowerShell History File...");
            string userPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string psHistoryPath = @"Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt";
            string psHistory = Path.Combine(userPath, psHistoryPath);
            if (File.Exists(psHistory))
            {
                Console.WriteLine("\tHistory File in: " + psHistory);
            }
            else Console.WriteLine("\t[-] PowerShell History file does not exist");


            //POWERSHELL SCRIPT LOGGING ENUMERATION   powershell脚本日志记录枚举
            Console.WriteLine("\n[+] Enumerating PowerShell Environment Config...");
            RegistryKey scriptLog_config = registryKey.OpenSubKey(@"Software\Policies\Microsoft\Windows\Powershell\ScriptBlockLogging");
            if (scriptLog_config != null)
            {
                var scLog = scriptLog_config.GetValue("EnableScriptBlockLogging");
                if (scLog.ToString().Equals("1"))
                {

                    Console.WriteLine("\t[!] ScriptBlock Logging is enabled");
                }
                else Console.WriteLine("\t[-] ScriptBlock Logging is Not enabled");
            }
            //POWERSHELL TRANSCRIPTION LOGGING  powershell转录日志记录

            RegistryKey transcriptLog_config = registryKey.OpenSubKey(@"Software\Policies\Microsoft\Windows\PowerShell\Transcription");
            if (transcriptLog_config != null)
            {
                var tsLog = transcriptLog_config.GetValue("EnableTranscripting");
                if (tsLog.ToString().Equals("1"))
                {
                    Console.WriteLine("\t[!] Transcript Logging is enabled");
                }
                else Console.WriteLine("\t[-] Transcript Logging is Not enabled");
            }

            //POWERSHELL CONSTRAINED MODES ENUMERATION  powershell约束模式枚举
            //1. Full Language
            //2. Restricted Language
            //3. No Language
            //4. Constrained Language
            Console.WriteLine("\n[+] Enumerating PowerShell Constrained Config...");
            RegistryKey constrainLog_config = registryKey.OpenSubKey(@"System\CurrentControlSet\Control\Session Manager\Environment");
            if (constrainLog_config != null)
            {
                if (constrainLog_config.GetValue("_PSLockdownPolicy") != null)
                {
                    var psPolicy = constrainLog_config.GetValue("_PSLockdownPolicy");
                    if (psPolicy.Equals("1"))
                    {
                        Console.WriteLine("\tFull Language Mode");
                    }
                    else if (psPolicy.Equals("2"))
                    {
                        Console.WriteLine("\tFull Language Mode");
                    }
                    else if (psPolicy.Equals("3"))
                    {
                        Console.WriteLine("\tNo Language Mode");
                    }
                    else if (psPolicy.Equals("4"))
                    {
                        Console.WriteLine("[!] Constrained Language Mode");
                    }

                }
                else Console.WriteLine("\t[-] PSLockdownPolicy in not enabled");
            }
        }

        public static void Csharp_Version()
        {
            Console.WriteLine("\n[+] Microsoft.NET Versions Installed");
            string[] Netdirectories = Directory.GetDirectories(@"C:\Windows\Microsoft.NET\Framework");
            for (int i = 0; i < Netdirectories.Length; i++)
            {
                Console.WriteLine("\t" + Netdirectories[i]);
            }
        }

        public static void AvProcessEDRproduct()
        {
            //ANTIVURUS PROCESSES
            string[] avproducts = { "Tanium.exe", "360RP.exe", "360SD.exe", "360Safe.exe", "360leakfixer.exe", "360rp.exe", "360safe.exe", "360sd.exe", "360tray.exe", "AAWTray.exe", "ACAAS.exe", "ACAEGMgr.exe", "ACAIS.exe", "AClntUsr.EXE", "ALERT.EXE", "ALERTSVC.EXE", "ALMon.exe", "ALUNotify.exe", "ALUpdate.exe", "ALsvc.exe", "AVENGINE.exe", "AVGCHSVX.EXE", "AVGCSRVX.EXE", "AVGIDSAgent.exe", "AVGIDSMonitor.exe", "AVGIDSUI.exe", "AVGIDSWatcher.exe", "AVGNSX.EXE", "AVKProxy.exe", "AVKService.exe", "AVKTray.exe", "AVKWCtl.exe", "AVP.EXE", "AVP.exe", "AVPDTAgt.exe", "AcctMgr.exe", "Ad-Aware.exe", "Ad-Aware2007.exe", "AddressExport.exe", "AdminServer.exe", "Administrator.exe", "AeXAgentUIHost.exe", "AeXNSAgent.exe", "AeXNSRcvSvc.exe", "AlertSvc.exe", "AlogServ.exe", "AluSchedulerSvc.exe", "AnVir.exe", "AppSvc32.exe", "AtrsHost.exe", "Auth8021x.exe", "AvastSvc.exe", "AvastUI.exe", "Avconsol.exe", "AvpM.exe", "Avsynmgr.exe", "Avtask.exe", "BLACKD.exe", "BWMeterConSvc.exe", "CAAntiSpyware.exe", "CALogDump.exe", "CAPPActiveProtection.exe", "CAPPActiveProtection.exe", "CB.exe", "CCAP.EXE", "CCenter.exe", "CClaw.exe", "CLPS.exe", "CLPSLA.exe", "CLPSLS.exe", "CNTAoSMgr.exe", "CPntSrv.exe", "CTDataLoad.exe", "CertificationManagerServiceNT.exe", "ClShield.exe", "ClamTray.exe", "ClamWin.exe", "Console.exe", "CylanceUI.exe", "DAO_Log.exe", "DLService.exe", "DLTray.EXE", "DLTray.exe", "DRWAGNTD.EXE", "DRWAGNUI.EXE", "DRWEB32W.EXE", "DRWEBSCD.EXE", "DRWEBUPW.EXE", "DRWINST.EXE", "DSMain.exe", "DWHWizrd.exe", "DefWatch.exe", "DolphinCharge.exe", "EHttpSrv.exe", "EMET_Agent.exe", "EMET_Service.exe", "EMLPROUI.exe", "EMLPROXY.exe", "EMLibUpdateAgentNT.exe", "ETConsole3.exe", "ETCorrel.exe", "ETLogAnalyzer.exe", "ETReporter.exe", "ETRssFeeds.exe", "EUQMonitor.exe", "EndPointSecurity.exe", "EngineServer.exe", "EntityMain.exe", "EtScheduler.exe", "EtwControlPanel.exe", "EventParser.exe", "FAMEH32.exe", "FCDBLog.exe", "FCH32.exe", "FPAVServer.exe", "FProtTray.exe", "FSCUIF.exe", "FSHDLL32.exe", "FSM32.exe", "FSMA32.exe", "FSMB32.exe", "FWCfg.exe", "FireSvc.exe", "FireTray.exe", "FirewallGUI.exe", "ForceField.exe", "FortiProxy.exe", "FortiTray.exe", "FortiWF.exe", "FrameworkService.exe", "FreeProxy.exe", "GDFirewallTray.exe", "GDFwSvc.exe", "HWAPI.exe", "ISNTSysMonitor.exe", "ISSVC.exe", "ISWMGR.exe", "ITMRTSVC.exe", "ITMRT_SupportDiagnostics.exe", "ITMRT_TRACE.exe", "IcePack.exe", "IdsInst.exe", "InoNmSrv.exe", "InoRT.exe", "InoRpc.exe", "InoTask.exe", "InoWeb.exe", "IsntSmtp.exe", "KABackReport.exe", "KANMCMain.exe", "KAVFS.EXE", "KAVStart.exe", "KLNAGENT.EXE", "KMailMon.exe", "KNUpdateMain.exe", "KPFWSvc.exe", "KSWebShield.exe", "KVMonXP.exe", "KVMonXP_2.exe", "KVSrvXP.exe", "KWSProd.exe", "KWatch.exe", "KavAdapterExe.exe", "KeyPass.exe", "KvXP.exe", "LUALL.EXE", "LWDMServer.exe", "LockApp.exe", "LockAppHost.exe", "LogGetor.exe", "MCSHIELD.EXE", "MCUI32.exe", "MSASCui.exe", "ManagementAgentNT.exe", "McAfeeDataBackup.exe", "McEPOC.exe", "McEPOCfg.exe", "McNASvc.exe", "McProxy.exe", "McScript_InUse.exe", "McWCE.exe", "McWCECfg.exe", "Mcshield.exe", "Mctray.exe", "MgntSvc.exe", "MpCmdRun.exe", "MpfAgent.exe", "MpfSrv.exe", "MsMpEng.exe", "NAIlgpip.exe", "NAVAPSVC.EXE", "NAVAPW32.EXE", "NCDaemon.exe", "NIP.exe", "NJeeves.exe", "NLClient.exe", "NMAGENT.EXE", "NOD32view.exe", "NPFMSG.exe", "NPROTECT.EXE", "NRMENCTB.exe", "NSMdtr.exe", "NTRtScan.exe", "NVCOAS.exe", "NVCSched.exe", "NavShcom.exe", "Navapsvc.exe", "NaveCtrl.exe", "NaveLog.exe", "NaveSP.exe", "Navw32.exe", "Navwnt.exe", "Nip.exe", "Njeeves.exe", "Npfmsg2.exe", "Npfsvice.exe", "NscTop.exe", "Nvcoas.exe", "Nvcsched.exe", "Nymse.exe", "OLFSNT40.EXE", "OMSLogManager.exe", "ONLINENT.exe", "ONLNSVC.exe", "OfcPfwSvc.exe", "PASystemTray.exe", "PAVFNSVR.exe", "PAVSRV51.exe", "PNmSrv.exe", "POPROXY.EXE", "POProxy.exe", "PPClean.exe", "PPCtlPriv.exe", "PQIBrowser.exe", "PSHost.exe", "PSIMSVC.EXE", "PXEMTFTP.exe", "PadFSvr.exe", "Pagent.exe", "Pagentwd.exe", "PavBckPT.exe", "PavFnSvr.exe", "PavPrSrv.exe", "PavProt.exe", "PavReport.exe", "Pavkre.exe", "PcCtlCom.exe", "PcScnSrv.exe", "PccNTMon.exe", "PccNTUpd.exe", "PpPpWallRun.exe", "PrintDevice.exe", "ProUtil.exe", "PsCtrlS.exe", "PsImSvc.exe", "PwdFiltHelp.exe", "Qoeloader.exe", "RAVMOND.exe", "RAVXP.exe", "RNReport.exe", "RPCServ.exe", "RSSensor.exe", "RTVscan.exe", "RapApp.exe", "Rav.exe", "RavAlert.exe", "RavMon.exe", "RavMonD.exe", "RavService.exe", "RavStub.exe", "RavTask.exe", "RavTray.exe", "RavUpdate.exe", "RavXP.exe", "RealMon.exe", "Realmon.exe", "RedirSvc.exe", "RegMech.exe", "ReporterSvc.exe", "RouterNT.exe", "Rtvscan.exe", "SAFeService.exe", "SAService.exe", "SAVAdminService.exe", "SAVFMSESp.exe", "SAVMain.exe", "SAVScan.exe", "SCANMSG.exe", "SCANWSCS.exe", "SCFManager.exe", "SCFService.exe", "SCFTray.exe", "SDTrayApp.exe", "SEVINST.EXE", "SMEX_ActiveUpdate.exe", "SMEX_Master.exe", "SMEX_RemoteConf.exe", "SMEX_SystemWatch.exe", "SMSECtrl.exe", "SMSELog.exe", "SMSESJM.exe", "SMSESp.exe", "SMSESrv.exe", "SMSETask.exe", "SMSEUI.exe", "SNAC.EXE", "SNAC.exe", "SNDMon.exe", "SNDSrvc.exe", "SPBBCSvc.exe", "SPIDERML.EXE", "SPIDERNT.EXE", "SSM.exe", "SSScheduler.exe", "SVCharge.exe", "SVDealer.exe", "SVFrame.exe", "SVTray.exe", "SWNETSUP.EXE", "SavRoam.exe", "SavService.exe", "SavUI.exe", "ScanMailOutLook.exe", "SeAnalyzerTool.exe", "SemSvc.exe", "SescLU.exe", "SetupGUIMngr.exe", "SiteAdv.exe", "Smc.exe", "SmcGui.exe", "SnHwSrv.exe", "SnICheckAdm.exe", "SnIcon.exe", "SnSrv.exe", "SnicheckSrv.exe", "SpIDerAgent.exe", "SpntSvc.exe", "SpyEmergency.exe", "SpyEmergencySrv.exe", "StOPP.exe", "StWatchDog.exe", "SymCorpUI.exe", "SymSPort.exe", "TBMon.exe", "TFGui.exe", "TFService.exe", "TFTray.exe", "TFun.exe", "TIASPN~1.EXE", "TSAnSrf.exe", "TSAtiSy.exe", "TScutyNT.exe", "TSmpNT.exe", "TmListen.exe", "TmPfw.exe", "Tmntsrv.exe", "Traflnsp.exe", "TrapTrackerMgr.exe", "UPSCHD.exe", "UcService.exe", "UdaterUI.exe", "UmxAgent.exe", "UmxCfg.exe", "UmxFwHlp.exe", "UmxPol.exe", "Up2date.exe", "UpdaterUI.exe", "UrlLstCk.exe", "UserActivity.exe", "UserAnalysis.exe", "UsrPrmpt.exe", "V3Medic.exe", "V3Svc.exe", "VPC32.exe", "VPDN_LU.exe", "VPTray.exe", "VSStat.exe", "VsStat.exe", "VsTskMgr.exe", "WEBPROXY.EXE", "WFXCTL32.EXE", "WFXMOD32.EXE", "WFXSNT40.EXE", "WebProxy.exe", "WebScanX.exe", "WinRoute.exe", "WrSpySetup.exe", "ZLH.exe", "Zanda.exe", "ZhuDongFangYu.exe", "Zlh.exe", "_avp32.exe", "_avpcc.exe", "_avpm.exe", "aAvgApi.exe", "aawservice.exe", "acaif.exe", "acctmgr.exe", "ackwin32.exe", "aclient.exe", "adaware.exe", "advxdwin.exe", "aexnsagent.exe", "aexsvc.exe", "aexswdusr.exe", "aflogvw.exe", "afwServ.exe", "agentsvr.exe", "agentw.exe", "ahnrpt.exe", "ahnsd.exe", "ahnsdsv.exe", "alertsvc.exe", "alevir.exe", "alogserv.exe", "alsvc.exe", "alunotify.exe", "aluschedulersvc.exe", "amon9x.exe", "amswmagt.exe", "anti-trojan.exe", "antiarp.exe", "antivirus.exe", "ants.exe", "aphost.exe", "apimonitor.exe", "aplica32.exe", "aps.exe", "apvxdwin.exe", "arr.exe", "ashAvast.exe", "ashBug.exe", "ashChest.exe", "ashCmd.exe", "ashDisp.exe", "ashEnhcd.exe", "ashLogV.exe", "ashMaiSv.exe", "ashPopWz.exe", "ashQuick.exe", "ashServ.exe", "ashSimp2.exe", "ashSimpl.exe", "ashSkPcc.exe", "ashSkPck.exe", "ashUpd.exe", "ashWebSv.exe", "ashdisp.exe", "ashmaisv.exe", "ashserv.exe", "ashwebsv.exe", "asupport.exe", "aswDisp.exe", "aswRegSvr.exe", "aswServ.exe", "aswUpdSv.exe", "aswUpdsv.exe", "aswWebSv.exe", "aswupdsv.exe", "atcon.exe", "atguard.exe", "atro55en.exe", "atupdater.exe", "atwatch.exe", "atwsctsk.exe", "au.exe", "aupdate.exe", "aupdrun.exe", "aus.exe", "auto-protect.nav80try.exe", "autodown.exe", "autotrace.exe", "autoup.exe", "autoupdate.exe", "avEngine.exe", "avadmin.exe", "avcenter.exe", "avconfig.exe", "avconsol.exe", "ave32.exe", "avengine.exe", "avesvc.exe", "avfwsvc.exe", "avgam.exe", "avgamsvr.exe", "avgas.exe", "avgcc.exe", "avgcc32.exe", "avgcsrvx.exe", "avgctrl.exe", "avgdiag.exe", "avgemc.exe", "avgfws8.exe", "avgfws9.exe", "avgfwsrv.exe", "avginet.exe", "avgmsvr.exe", "avgnsx.exe", "avgnt.exe", "avgregcl.exe", "avgrssvc.exe", "avgrsx.exe", "avgscanx.exe", "avgserv.exe", "avgserv9.exe", "avgsystx.exe", "avgtray.exe", "avguard.exe", "avgui.exe", "avgupd.exe", "avgupdln.exe", "avgupsvc.exe", "avgvv.exe", "avgw.exe", "avgwb.exe", "avgwdsvc.exe", "avgwizfw.exe", "avkpop.exe", "avkserv.exe", "avkservice.exe", "avkwctl9.exe", "avltmain.exe", "avmailc.exe", "avmcdlg.exe", "avnotify.exe", "avnt.exe", "avp.exe", "avp32.exe", "avpcc.exe", "avpdos32.exe", "avpexec.exe", "avpm.exe", "avpncc.exe", "avps.exe", "avptc32.exe", "avpupd.exe", "avscan.exe", "avsched32.exe", "avserver.exe", "avshadow.exe", "avsynmgr.exe", "avwebgrd.exe", "avwin.exe", "avwin95.exe", "avwinnt.exe", "avwupd.exe", "avwupd32.exe", "avwupsrv.exe", "avxmonitor9x.exe", "avxmonitornt.exe", "avxquar.exe", "backweb.exe", "bargains.exe", "basfipm.exe", "bd_professional.exe", "bdagent.exe", "bdc.exe", "bdlite.exe", "bdmcon.exe", "bdss.exe", "bdsubmit.exe", "beagle.exe", "belt.exe", "bidef.exe", "bidserver.exe", "bipcp.exe", "bipcpevalsetup.exe", "bisp.exe", "blackd.exe", "blackice.exe", "blink.exe", "blss.exe", "bmrt.exe", "bootconf.exe", "bootwarn.exe", "borg2.exe", "bpc.exe", "bpk.exe", "brasil.exe", "bs120.exe", "bundle.exe", "bvt.exe", "bwgo0000.exe", "ca.exe", "caav.exe", "caavcmdscan.exe", "caavguiscan.exe", "caf.exe", "cafw.exe", "caissdt.exe", "capfaem.exe", "capfasem.exe", "capfsem.exe", "capmuamagt.exe", "casc.exe", "casecuritycenter.exe", "caunst.exe", "cavrep.exe", "cavrid.exe", "cavscan.exe", "cavtray.exe", "ccApp.exe", "ccEvtMgr.exe", "ccLgView.exe", "ccProxy.exe", "ccSetMgr.exe", "ccSetmgr.exe", "ccSvcHst.exe", "ccap.exe", "ccapp.exe", "ccevtmgr.exe", "cclaw.exe", "ccnfagent.exe", "ccprovsp.exe", "ccproxy.exe", "ccpxysvc.exe", "ccschedulersvc.exe", "ccsetmgr.exe", "ccsmagtd.exe", "ccsvchst.exe", "ccsystemreport.exe", "cctray.exe", "ccupdate.exe", "cdp.exe", "cfd.exe", "cfftplugin.exe", "cfgwiz.exe", "cfiadmin.exe", "cfiaudit.exe", "cfinet.exe", "cfinet32.exe", "cfnotsrvd.exe", "cfp.exe", "cfpconfg.exe", "cfpconfig.exe", "cfplogvw.exe", "cfpsbmit.exe", "cfpupdat.exe", "cfsmsmd.exe", "checkup.exe", "cka.exe", "clamscan.exe", "claw95.exe", "claw95cf.exe", "clean.exe", "cleaner.exe", "cleaner3.exe", "cleanpc.exe", "cleanup.exe", "click.exe", "cmdagent.exe", "cmdinstall.exe", "cmesys.exe", "cmgrdian.exe", "cmon016.exe", "comHost.exe", "connectionmonitor.exe", "control_panel.exe", "cpd.exe", "cpdclnt.exe", "cpf.exe", "cpf9x206.exe", "cpfnt206.exe", "crashrep.exe", "csacontrol.exe", "csinject.exe", "csinsm32.exe", "csinsmnt.exe", "csrss_tc.exe", "ctrl.exe", "cv.exe", "cwnb181.exe", "cwntdwmo.exe", "cz.exe", "datemanager.exe", "dbserv.exe", "dbsrv9.exe", "dcomx.exe", "defalert.exe", "defscangui.exe", "defwatch.exe", "deloeminfs.exe", "deputy.exe", "diskmon.exe", "divx.exe", "djsnetcn.exe", "dllcache.exe", "dllreg.exe", "doors.exe", "doscan.exe", "dpf.exe", "dpfsetup.exe", "dpps2.exe", "drwagntd.exe", "drwatson.exe", "drweb.exe", "drweb32.exe", "drweb32w.exe", "drweb386.exe", "drwebcgp.exe", "drwebcom.exe", "drwebdc.exe", "drwebmng.exe", "drwebscd.exe", "drwebupw.exe", "drwebwcl.exe", "drwebwin.exe", "drwupgrade.exe", "dsmain.exe", "dssagent.exe", "dvp95.exe", "dvp95_0.exe", "dwengine.exe", "dwhwizrd.exe", "dwwin.exe", "ecengine.exe", "edisk.exe", "efpeadm.exe", "egui.exe", "ekrn.exe", "elogsvc.exe", "emet_agent.exe", "emet_service.exe", "emsw.exe", "engineserver.exe", "ent.exe", "era.exe", "esafe.exe", "escanhnt.exe", "escanv95.exe", "esecagntservice.exe", "esecservice.exe", "esmagent.exe", "espwatch.exe", "etagent.exe", "ethereal.exe", "etrustcipe.exe", "evpn.exe", "evtProcessEcFile.exe", "evtarmgr.exe", "evtmgr.exe", "exantivirus-cnet.exe", "exe.avxw.exe", "execstat.exe", "expert.exe", "explore.exe", "f-agnt95.exe", "f-prot.exe", "f-prot95.exe", "f-stopw.exe", "fameh32.exe", "fast.exe", "fch32.exe", "fih32.exe", "findviru.exe", "firesvc.exe", "firetray.exe", "firewall.exe", "fmon.exe", "fnrb32.exe", "fortifw.exe", "fp-win.exe", "fp-win_trial.exe", "fprot.exe", "frameworkservice.exe", "frminst.exe", "frw.exe", "fsaa.exe", "fsaua.exe", "fsav.exe", "fsav32.exe", "fsav530stbyb.exe", "fsav530wtbyb.exe", "fsav95.exe", "fsavgui.exe", "fscuif.exe", "fsdfwd.exe", "fsgk32.exe", "fsgk32st.exe", "fsguidll.exe", "fsguiexe.exe", "fshdll32.exe", "fsm32.exe", "fsma32.exe", "fsmb32.exe", "fsorsp.exe", "fspc.exe", "fspex.exe", "fsqh.exe", "fssm32.exe", "fwinst.exe", "gator.exe", "gbmenu.exe", "gbpoll.exe", "gcascleaner.exe", "gcasdtserv.exe", "gcasinstallhelper.exe", "gcasnotice.exe", "gcasserv.exe", "gcasservalert.exe", "gcasswupdater.exe", "generics.exe", "gfireporterservice.exe", "ghost_2.exe", "ghosttray.exe", "giantantispywaremain.exe", "giantantispywareupdater.exe", "gmt.exe", "guard.exe", "guarddog.exe", "guardgui.exe", "hacktracersetup.exe", "hbinst.exe", "hbsrv.exe", "hipsvc.exe", "hotactio.exe", "hotpatch.exe", "htlog.exe", "htpatch.exe", "hwpe.exe", "hxdl.exe", "hxiul.exe", "iamapp.exe", "iamserv.exe", "iamstats.exe", "ibmasn.exe", "ibmavsp.exe", "icepack.exe", "icload95.exe", "icloadnt.exe", "icmon.exe", "icsupp95.exe", "icsuppnt.exe", "idle.exe", "iedll.exe", "iedriver.exe", "iface.exe", "ifw2000.exe", "igateway.exe", "inetlnfo.exe", "infus.exe", "infwin.exe", "inicio.exe", "init.exe", "inonmsrv.exe", "inorpc.exe", "inort.exe", "inotask.exe", "intdel.exe", "intren.exe", "iomon98.exe", "isPwdSvc.exe", "isUAC.exe", "isafe.exe", "isafinst.exe", "issvc.exe", "istsvc.exe", "jammer.exe", "jdbgmrg.exe", "jedi.exe", "kaccore.exe", "kansgui.exe", "kansvr.exe", "kastray.exe", "kav.exe", "kav32.exe", "kavfs.exe", "kavfsgt.exe", "kavfsrcn.exe", "kavfsscs.exe", "kavfswp.exe", "kavisarv.exe", "kavlite40eng.exe", "kavlotsingleton.exe", "kavmm.exe", "kavpers40eng.exe", "kavpf.exe", "kavshell.exe", "kavss.exe", "kavstart.exe", "kavsvc.exe", "kavtray.exe", "kazza.exe", "keenvalue.exe", "kerio-pf-213-en-win.exe", "kerio-wrl-421-en-win.exe", "kerio-wrp-421-en-win.exe", "kernel32.exe", "killprocesssetup161.exe", "kis.exe", "kislive.exe", "kissvc.exe", "klnacserver.exe", "klnagent.exe", "klserver.exe", "klswd.exe", "klwtblfs.exe", "kmailmon.exe", "knownsvr.exe", "kpf4gui.exe", "kpf4ss.exe", "kpfw32.exe", "kpfwsvc.exe", "krbcc32s.exe", "kvdetech.exe", "kvolself.exe", "kvsrvxp.exe", "kvsrvxp_1.exe", "kwatch.exe", "kwsprod.exe", "kxeserv.exe", "launcher.exe", "ldnetmon.exe", "ldpro.exe", "ldpromenu.exe", "ldscan.exe", "leventmgr.exe", "livesrv.exe", "lmon.exe", "lnetinfo.exe", "loader.exe", "localnet.exe", "lockdown.exe", "lockdown2000.exe", "log_qtine.exe", "lookout.exe", "lordpe.exe", "lsetup.exe", "luall.exe", "luau.exe", "lucallbackproxy.exe", "lucoms.exe", "lucomserver.exe", "lucoms~1.exe", "luinit.exe", "luspt.exe", "makereport.exe", "mantispm.exe", "mapisvc32.exe", "masalert.exe", "massrv.exe", "mcafeefire.exe", "mcagent.exe", "mcappins.exe", "mcconsol.exe", "mcdash.exe", "mcdetect.exe", "mcepoc.exe", "mcepocfg.exe", "mcinfo.exe", "mcmnhdlr.exe", "mcmscsvc.exe", "mcods.exe", "mcpalmcfg.exe", "mcpromgr.exe", "mcregwiz.exe", "mcscript.exe", "mcscript_inuse.exe", "mcshell.exe", "mcshield.exe", "mcshld9x.exe", "mcsysmon.exe", "mctool.exe", "mctray.exe", "mctskshd.exe", "mcuimgr.exe", "mcupdate.exe", "mcupdmgr.exe", "mcvsftsn.exe", "mcvsrte.exe", "mcvsshld.exe", "mcwce.exe", "mcwcecfg.exe", "md.exe", "mfeann.exe", "mfevtps.exe", "mfin32.exe", "mfw2en.exe", "mfweng3.02d30.exe", "mgavrtcl.exe", "mgavrte.exe", "mghtml.exe", "mgui.exe", "minilog.exe", "mmod.exe", "monitor.exe", "monsvcnt.exe", "monsysnt.exe", "moolive.exe", "mostat.exe", "mpcmdrun.exe", "mpf.exe", "mpfagent.exe", "mpfconsole.exe", "mpfservice.exe", "mpftray.exe", "mps.exe", "mpsevh.exe", "mpsvc.exe", "mrf.exe", "mrflux.exe", "msapp.exe", "msascui.exe", "msbb.exe", "msblast.exe", "mscache.exe", "msccn32.exe", "mscifapp.exe", "mscman.exe", "msconfig.exe", "msdm.exe", "msdos.exe", "msiexec16.exe", "mskagent.exe", "mskdetct.exe", "msksrver.exe", "msksrvr.exe", "mslaugh.exe", "msmgt.exe", "msmpeng.exe", "msmsgri32.exe", "msscli.exe", "msseces.exe", "mssmmc32.exe", "msssrv.exe", "mssys.exe", "msvxd.exe", "mu0311ad.exe", "mwatch.exe", "myagttry.exe", "n32scanw.exe", "nSMDemf.exe", "nSMDmon.exe", "nSMDreal.exe", "nSMDsch.exe", "naPrdMgr.exe", "nav.exe", "navap.navapsvc.exe", "navapsvc.exe", "navapw32.exe", "navdx.exe", "navlu32.exe", "navnt.exe", "navstub.exe", "navw32.exe", "navwnt.exe", "nc2000.exe", "ncinst4.exe" };
            Process[] procs = Process.GetProcesses(Environment.MachineName);
            Console.WriteLine("\n[+] Checking for  Antivirus Processes on " + Environment.MachineName + "...");
            Console.WriteLine("[*] Loaded " + avproducts.Length + " AV Process Names");

            for (int i = 0; i < procs.Length; i++)
            {
                for (int a = 0; a < avproducts.Length; a++)
                {
                    string processSearch = avproducts[a].Substring(0, avproducts[a].Length - 4);
                    if (procs[i].ProcessName.Equals(processSearch))
                    {
                        Console.WriteLine("\t[!] Found AV Process: " + procs[i].ProcessName);
                    }
                }
            }

            //EDR PRODUCTS
            string[] edrproducts = { "cbstream.sys", "cbk7.sys", "Parity.sys", "libwamf.sys", "LRAgentMF.sys", "BrCow_x_x_x_x.sys", "brfilter.sys", "BDSandBox.sys", "AVC3.SYS", "TRUFOS.SYS", "Atc.sys", "AVCKF.SYS", "bddevflt.sys", "gzflt.sys", "bdsvm.sys", "hbflt.sys", "cve.sys", "psepfilter.sys", "cposfw.sys", "dsfa.sys", "medlpflt.sys", "epregflt.sys", "TmFileEncDmk.sys", "tmevtmgr.sys", "TmEsFlt.sys", "fileflt.sys", "SakMFile.sys", "SakFile.sys", "AcDriver.sys", "TMUMH.sys", "hfileflt.sys", "TMUMS.sys", "MfeEEFF.sys", "mfprom.sys", "hdlpflt.sys", "swin.sys", "mfehidk.sys", "mfencoas.sys", "epdrv.sys", "carbonblackk.sys", "csacentr.sys", "csaenh.sys", "csareg.sys", "csascr.sys", "csaav.sys", "csaam.sys", "esensor.sys", "fsgk.sys", "fsatp.sys", "fshs.sys", "eaw.sys", "im.sys", "csagent.sys", "rvsavd.sys", "dgdmk.sys", "atrsdfw.sys", "mbamwatchdog.sys", "edevmon.sys", "SentinelMonitor.sys", "edrsensor.sys", "ehdrv.sys", "HexisFSMonitor.sys", "CyOptics.sys", "CarbonBlackK.sys", "CyProtectDrv32.sys", "CyProtectDrv64.sys", "CRExecPrev.sys", "ssfmonm.sys", "CybKernelTracker.sys", "SAVOnAccess.sys", "savonaccess.sys", "sld.sys", "aswSP.sys", "FeKern.sys", "klifks.sys", "klifaa.sys", "Klifsm.sys", "mfeaskm.sys", "mfencfilter.sys", "WFP_MRT.sys", "groundling32.sys", "SAFE-Agent.sys", "groundling64.sys", "avgtpx86.sys", "avgtpx64.sys", "pgpwdefs.sys", "GEProtection.sys", "diflt.sys", "sysMon.sys", "ssrfsf.sys", "emxdrv2.sys", "reghook.sys", "spbbcdrv.sys", "bhdrvx86.sys", "bhdrvx64.sys", "SISIPSFileFilter.sys", "symevent.sys", "VirtualAgent.sys", "vxfsrep.sys", "VirtFile.sys", "SymAFR.sys", "symefasi.sys", "symefa.sys", "symefa64.sys", "SymHsm.sys", "evmf.sys", "GEFCMP.sys", "VFSEnc.sys", "pgpfs.sys", "fencry.sys", "symrg.sys", "cfrmd.sys", "cmdccav.sys", "cmdguard.sys", "CmdMnEfs.sys", "MyDLPMF.sys", "PSINPROC.SYS", "PSINFILE.SYS", "amfsm.sys", "amm8660.sys", "amm6460.sys" };
            Console.WriteLine("\n[+] Enumerating EDR products on " + Environment.MachineName + "...");
            Console.WriteLine("[*] Loaded " + edrproducts.Length + " EDR Product Names");
            string edrPath = @"C:\Windows\System32\drivers\";
            for (int e = 0; e < edrproducts.Length; e++)
            {
                if (File.Exists(edrPath + edrproducts[e]))
                {
                    Console.WriteLine("\t[!] EDR driver found " + edrproducts[e]);
                }
            }
        }

        public static void Defender()
        {

            //WINDOWS DEFENDER CONFIGURATION AND EXCEPTIONS  配置
            Console.WriteLine("\n[+] Enumerating Windows Defender Config...");
            RegistryKey folder_exclusions = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths");
            Console.WriteLine("\tEnumerating Windows Defender Path Exclusions...");
            if (folder_exclusions != null)
            {

                for (int i = 0; i < folder_exclusions.GetValueNames().Length; i++)
                {
                    Console.WriteLine("\t[+] " + folder_exclusions.GetValueNames()[i]);
                }
                Console.WriteLine();
            }
            //WINDOWS DEFENDER EXCLUSIONS  WINDOWS DEFENDER 排除项
            Console.WriteLine("\tEnumerating Windows Defender Extensions Exclusions...");
            RegistryKey ext_exclusions = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions");

            if (ext_exclusions == null)
            {
                Console.WriteLine("\tNo extensions exclusions specified");
            }
            else
            {
                if (ext_exclusions.GetValueNames().Length > 0)
                {
                    for (int i = 0; i < ext_exclusions.GetValueNames().Length; i++)
                    {
                        Console.WriteLine("\t[+]" + ext_exclusions.GetValueNames()[i]);
                    }
                }
                else
                {
                    Console.WriteLine("\t[-] No extensions exclusions specified.");
                }

            }
        }

        public static void Recent_files()
        {
            //WINDOWS RECENT FILES   Windows最近使用的文件
            string recents = @"Microsoft\Windows\Recent";
            string userPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string recentsPath = Path.Combine(userPath, recents);
            DirectoryInfo di = new DirectoryInfo(recentsPath);
            Console.WriteLine("\n[+] Recent Items in " + recentsPath);
            foreach (var file in di.GetFiles())
            {
                Console.WriteLine("\t" + file.Name);
            }
        }

        public static void Network_Connentions()
        {
            //NETWORK CONNECTIONS  网络连接
            Console.WriteLine("\n[+] Enumerating Network Connections...");
            IPGlobalProperties ipProperties = IPGlobalProperties.GetIPGlobalProperties();
            IPEndPoint[] endPoints = ipProperties.GetActiveTcpListeners();
            TcpConnectionInformation[] tcpConnections = ipProperties.GetActiveTcpConnections();
            foreach (TcpConnectionInformation info in tcpConnections)
            {
                Console.WriteLine("\tLocal : " + info.LocalEndPoint.Address.ToString() + ":" + info.LocalEndPoint.Port.ToString() + " - Remote : " + info.RemoteEndPoint.Address.ToString() + ":" + info.RemoteEndPoint.Port.ToString());
            }
        }

        public static void Applocker_Enumerating()
        {
            //CHECK FOR REGISTRY x64/x32   检查注册表
            var registryKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            RegistryKey key = registryKey.OpenSubKey("Software");
            if (key == null)
            {
                registryKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
            }
            //APPLOCKER ENUMERATION  applocker枚举
            Console.WriteLine("\n[+] Enumerating Applocker Config...");
            RegistryKey appLocker_config = registryKey.OpenSubKey(@"Software\Policies\Microsoft\Windows\SrpV2\Exe");
            if (appLocker_config != null)
            {
                for (int i = 0; i < appLocker_config.SubKeyCount; i++)
                {
                    Console.WriteLine(appLocker_config.OpenSubKey(appLocker_config.GetSubKeyNames()[i]).GetValue("Value"));
                }
            }
        }

        public static void Drives()
        {
            //ATTACHED DRIVES  磁盘情况
            Console.WriteLine("\n[+] Enumerating Drives...");
            DriveInfo[] drives = DriveInfo.GetDrives();
            foreach (DriveInfo d in drives)
            {
                if (d.IsReady == true)
                {
                    Console.WriteLine("\tDrive " + d.Name + " " + d.DriveType + " - Size:" + d.TotalSize + " bytes");
                }
            }
        }

        public static void LAPS()
        {
            //LAPS
            Console.WriteLine("\n[+] Checking if LAPS is used...");
            string laps_path = @"C:\Program Files\LAPS\CSE\Admpwd.dll";
            Console.WriteLine(File.Exists(laps_path) ? "\t[!] LAPS is enabled" : "\t[-] LAPS is not enabled");

        }
    }
}

