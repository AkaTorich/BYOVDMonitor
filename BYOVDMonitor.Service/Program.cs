using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Principal;
using System.ServiceProcess;

namespace BYOVDMonitor.Service
{
    internal static class Program
    {
        public const string ServiceName = "BYOVDMonitor";
        public const string DisplayName = "BYOVD Monitor";
        public const string Description =
            "Detects known vulnerable drivers by hashing files in monitored folders " +
            "and comparing SHA-256 against loldrivers.io (offline) and Team Cymru MHR (optional, DNS).";
        public const string EventLogSource = "BYOVDMonitor";

        // Каталог данных службы — общий для всех пользователей, не в профиле.
        public static readonly string ServiceDataDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "BYOVDMonitor");

        private static int Main(string[] args)
        {
            // ВАЖНО: переопределяем каталог данных ДО первого обращения к AppConfig.
            AppConfig.DataDirectory = ServiceDataDirectory;

            if (args == null || args.Length == 0)
            {
                // Обычный запуск из диспетчера служб Windows.
                ServiceBase.Run(new ServiceBase[] { new WorkerService() });
                return 0;
            }

            string cmd = args[0].ToLowerInvariant();
            try
            {
                switch (cmd)
                {
                    case "install":   return Install();
                    case "uninstall": return Uninstall();
                    case "start":     return RunSc("start " + ServiceName);
                    case "stop":      return RunSc("stop " + ServiceName);
                    case "status":    return RunSc("query " + ServiceName);
                    case "console":   return RunConsole();
                    case "config":    return ShowConfigPath();
                    case "help":
                    case "-h":
                    case "--help":
                    case "/?":        PrintUsage(); return 0;
                    default:
                        Console.Error.WriteLine("Unknown command: " + cmd);
                        PrintUsage();
                        return 1;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error: " + ex.Message);
                return 1;
            }
        }

        private static void PrintUsage()
        {
            Console.WriteLine("BYOVD Monitor Service");
            Console.WriteLine("Usage: BYOVDMonitorService.exe <command>");
            Console.WriteLine();
            Console.WriteLine("Commands:");
            Console.WriteLine("  install     Register and start the Windows service (run as admin)");
            Console.WriteLine("  uninstall   Stop and unregister the service (run as admin)");
            Console.WriteLine("  start       Start the service");
            Console.WriteLine("  stop        Stop the service");
            Console.WriteLine("  status      Show service status");
            Console.WriteLine("  console     Run the service core in the current console (for debugging)");
            Console.WriteLine("  config      Print path to config.json");
            Console.WriteLine();
            Console.WriteLine("Data directory: " + ServiceDataDirectory);
            Console.WriteLine("Service runs as LocalSystem. Edit config.json to set monitored folders,");
            Console.WriteLine("optional webhook URL, MHR toggle, etc., then restart the service.");
        }

        private static int Install()
        {
            RequireAdmin();

            string exePath = Assembly.GetExecutingAssembly().Location;
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                throw new InvalidOperationException("Cannot resolve service executable path.");

            // Подготовка каталога данных и его прав доступа: писать могут только SYSTEM и Administrators.
            // Это блокирует «отравление» локальной базы папок (baseline) пользователем без прав.
            Directory.CreateDirectory(ServiceDataDirectory);
            HardenAcl(ServiceDataDirectory);

            // Создание источника журнала событий (нужны права администратора, делается один раз).
            if (!EventLog.SourceExists(EventLogSource))
            {
                EventLog.CreateEventSource(new EventSourceCreationData(EventLogSource, "Application"));
                Console.WriteLine("Event log source created: " + EventLogSource);
            }

            // Стартовый файл настроек (если ещё нет) — чтобы было что редактировать.
            string configPath = Path.Combine(ServiceDataDirectory, "config.json");
            if (!File.Exists(configPath))
            {
                new AppConfig().Save();
                Console.WriteLine("Default config written: " + configPath);
            }

            // Регистрация службы через sc.exe (binPath обязательно с пробелом ПОСЛЕ = ).
            string scCreateArgs =
                "create " + ServiceName +
                " binPath= \"\\\"" + exePath + "\\\"\"" +
                " start= auto" +
                " DisplayName= \"" + DisplayName + "\"";
            int rc = RunSc(scCreateArgs);
            if (rc != 0 && rc != 1073) // 1073 = служба уже существует
                return rc;

            RunSc("description " + ServiceName + " \"" + Description + "\"");
            // Перезапуск при сбое: 60 сек, 60 сек, 60 сек.
            RunSc("failure " + ServiceName + " reset= 86400 actions= restart/60000/restart/60000/restart/60000");

            Console.WriteLine("Service installed. Starting...");
            RunSc("start " + ServiceName);
            Console.WriteLine();
            Console.WriteLine("Edit config: " + configPath);
            Console.WriteLine("Then: " + Path.GetFileName(exePath) + " stop && " + Path.GetFileName(exePath) + " start");
            return 0;
        }

        private static int Uninstall()
        {
            RequireAdmin();

            // Останавливаем, ошибки игнорируем (служба могла уже не работать).
            RunSc("stop " + ServiceName);
            int rc = RunSc("delete " + ServiceName);
            if (rc != 0 && rc != 1060) // 1060 = служба не существует
                Console.WriteLine("sc delete returned " + rc);

            try
            {
                if (EventLog.SourceExists(EventLogSource))
                {
                    EventLog.DeleteEventSource(EventLogSource);
                    Console.WriteLine("Event log source removed.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Could not remove event log source: " + ex.Message);
            }

            Console.WriteLine("Data directory left intact: " + ServiceDataDirectory);
            return 0;
        }

        private static int RunConsole()
        {
            // Полезно для отладки на сервере: запуск тех же шагов, что и в режиме службы,
            // но с выводом в консоль и без диспетчера служб.
            Directory.CreateDirectory(ServiceDataDirectory);
            // Источник журнала событий лучше создать заранее (install), но в крайнем случае
            // WriteEntry просто молча провалится — это не критично для отладки.
            var worker = new WorkerService();
            worker.RunConsole();
            return 0;
        }

        private static int ShowConfigPath()
        {
            string p = Path.Combine(ServiceDataDirectory, "config.json");
            Console.WriteLine(p);
            return File.Exists(p) ? 0 : 2;
        }

        // Запуск sc.exe с выводом в текущую консоль; возвращает его код выхода.
        private static int RunSc(string arguments)
        {
            var psi = new ProcessStartInfo("sc.exe", arguments)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = false,
                RedirectStandardError = false
            };
            using (Process p = Process.Start(psi))
            {
                p.WaitForExit();
                return p.ExitCode;
            }
        }

        // ACL: только SYSTEM и Administrators имеют полный доступ; наследование отключено.
        private static void HardenAcl(string path)
        {
            var psi = new ProcessStartInfo("icacls.exe",
                "\"" + path + "\" /inheritance:r /grant:r \"*S-1-5-18:(OI)(CI)F\" \"*S-1-5-32-544:(OI)(CI)F\" /T")
            {
                UseShellExecute = false,
                CreateNoWindow = true
            };
            try
            {
                using (Process p = Process.Start(psi))
                {
                    p.WaitForExit();
                    if (p.ExitCode != 0)
                        Console.WriteLine("icacls returned " + p.ExitCode + " (continuing).");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("icacls failed: " + ex.Message + " (continuing).");
            }
        }

        private static void RequireAdmin()
        {
            using (var identity = WindowsIdentity.GetCurrent())
            {
                var principal = new WindowsPrincipal(identity);
                if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
                    throw new InvalidOperationException(
                        "This command requires elevation. Run from an Administrator command prompt.");
            }
        }
    }
}
