using System;
using System.Diagnostics.Eventing.Reader;
using System.IO;

namespace BYOVDMonitor
{
    // Сведения об установке драйвера, вытащенные из события журнала.
    public class DriverInstallInfo
    {
        public string ServiceName;   // имя службы/драйвера
        public string ImagePath;     // как записано в событии (может быть \??\, \SystemRoot\ и т. п.)
        public string ResolvedPath;  // нормализованный путь к .sys на диске (может быть null)
        public string ServiceType;   // "kernel mode driver" и пр.
        public string Origin;        // "7045" | "4697" — какое событие дало запись
    }

    // Наблюдение за САМОЙ установкой драйвера, а не только за появлением файла в наблюдаемой папке.
    // Реальная BYOVD-атака кладёт драйвер в случайную папку (temp) и регистрирует его как службу-драйвер —
    // мимо списка наблюдаемых папок. Здесь мы подписываемся на события журнала Windows:
    //   System  / Service Control Manager / 7045  — «служба установлена» (работает без доп. прав);
    //   Security / Microsoft-Windows-Security-Auditing / 4697 — «служба установлена» (нужны права и
    //           включённый аудит «Audit Security System Extension»; подписка best-effort).
    // На каждое событие установки драйвера поднимается Installed — движок затем хеширует файл
    // и сверяет его с базой уязвимых драйверов (по любому пути на диске).
    //
    // Всё в user mode: чтение журнала событий не требует собственного драйвера.
    public class DriverLoadWatcher
    {
        public event Action<DriverInstallInfo> Installed;
        public event Action<string> Error;

        private EventLogWatcher _systemWatcher;   // 7045
        private EventLogWatcher _securityWatcher;  // 4697

        public void Start()
        {
            Stop();

            // System / SCM / 7045 — «A service was installed in the system».
            _systemWatcher = TrySubscribe(
                "System",
                "*[System[Provider[@Name='Service Control Manager'] and (EventID=7045)]]",
                OnSystemEvent,
                "System log (7045)");

            // Security / 4697 — тот же факт, но из аудита. Доступно не всегда — не считаем ошибкой.
            _securityWatcher = TrySubscribe(
                "Security",
                "*[System[(EventID=4697)]]",
                OnSecurityEvent,
                null); // молча: аудит часто выключен/нет прав
        }

        public void Stop()
        {
            DisposeWatcher(ref _systemWatcher);
            DisposeWatcher(ref _securityWatcher);
        }

        private EventLogWatcher TrySubscribe(string logName, string xpath,
            EventHandler<EventRecordWrittenEventArgs> handler, string label)
        {
            try
            {
                var query = new EventLogQuery(logName, PathType.LogName, xpath);
                var watcher = new EventLogWatcher(query);
                watcher.EventRecordWritten += handler;
                watcher.Enabled = true;
                return watcher;
            }
            catch (Exception ex)
            {
                if (label != null)
                    RaiseError("Driver-load watch unavailable on " + label + ": " + ex.Message);
                return null;
            }
        }

        private static void DisposeWatcher(ref EventLogWatcher watcher)
        {
            if (watcher == null) return;
            try { watcher.Enabled = false; } catch { }
            try { watcher.Dispose(); } catch { }
            watcher = null;
        }

        // 7045: порядок полей — ServiceName, ImagePath, ServiceType, StartType, AccountName.
        private void OnSystemEvent(object sender, EventRecordWrittenEventArgs e)
        {
            if (e.EventRecord == null) return;
            try
            {
                var props = e.EventRecord.Properties;
                string serviceName = PropAt(props, 0);
                string imagePath = PropAt(props, 1);
                string serviceType = PropAt(props, 2);

                if (!LooksLikeDriver(serviceType)) return;
                Emit(serviceName, imagePath, serviceType, "7045");
            }
            catch (Exception ex)
            {
                RaiseError("Failed to read 7045 event: " + ex.Message);
            }
            finally
            {
                try { e.EventRecord.Dispose(); } catch { }
            }
        }

        // 4697: поля различаются по версиям; ImagePath обычно ServiceFileName, тип — ServiceType.
        // Берём поля по имени через XML, чтобы не зависеть от порядка.
        private void OnSecurityEvent(object sender, EventRecordWrittenEventArgs e)
        {
            if (e.EventRecord == null) return;
            try
            {
                string xml = e.EventRecord.ToXml();
                string serviceName = XmlData(xml, "ServiceName");
                string imagePath = XmlData(xml, "ServiceFileName");
                string serviceType = XmlData(xml, "ServiceType");

                // В 4697 ServiceType — числовой код; 0x1/0x2 — драйверы ядра/ФС.
                bool driver = LooksLikeDriver(serviceType)
                    || serviceType == "0x1" || serviceType == "0x2"
                    || (imagePath != null && imagePath.EndsWith(".sys", StringComparison.OrdinalIgnoreCase));
                if (!driver) return;

                Emit(serviceName, imagePath, serviceType, "4697");
            }
            catch (Exception ex)
            {
                RaiseError("Failed to read 4697 event: " + ex.Message);
            }
            finally
            {
                try { e.EventRecord.Dispose(); } catch { }
            }
        }

        private void Emit(string serviceName, string imagePath, string serviceType, string origin)
        {
            var info = new DriverInstallInfo
            {
                ServiceName = serviceName,
                ImagePath = imagePath,
                ResolvedPath = ResolveImagePath(imagePath),
                ServiceType = serviceType,
                Origin = origin
            };
            Action<DriverInstallInfo> handler = Installed;
            if (handler != null) handler(info);
        }

        private static bool LooksLikeDriver(string serviceType)
        {
            if (string.IsNullOrEmpty(serviceType)) return false;
            string t = serviceType.ToLowerInvariant();
            return t.Contains("driver"); // "kernel mode driver", "file system driver"
        }

        // Нормализация ImagePath из события в реальный путь к файлу .sys.
        // Учитываем \??\, \SystemRoot\, system32\..., переменные окружения, кавычки и хвост с аргументами.
        internal static string ResolveImagePath(string imagePath)
        {
            if (string.IsNullOrEmpty(imagePath)) return null;
            string p = imagePath.Trim().Trim('"');

            // Отрезаем аргументы после ".sys", если они есть.
            int sysIdx = p.IndexOf(".sys", StringComparison.OrdinalIgnoreCase);
            if (sysIdx >= 0) p = p.Substring(0, sysIdx + 4);

            // Префиксы NT-пространства имён.
            if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p.Substring(4);

            string windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
                p = Path.Combine(windir, p.Substring(@"\SystemRoot\".Length));
            else if (p.StartsWith("%SystemRoot%", StringComparison.OrdinalIgnoreCase))
                p = Path.Combine(windir, p.Substring("%SystemRoot%".Length).TrimStart('\\'));

            try { p = Environment.ExpandEnvironmentVariables(p); } catch { }

            // Относительный путь (например, "system32\drivers\foo.sys") — считаем от %WinDir%.
            try
            {
                if (!Path.IsPathRooted(p))
                    p = Path.Combine(windir, p);
                return Path.GetFullPath(p);
            }
            catch
            {
                return p;
            }
        }

        private static string PropAt(System.Collections.Generic.IList<EventProperty> props, int index)
        {
            if (props == null || index < 0 || index >= props.Count) return null;
            EventProperty prop = props[index];
            return prop != null && prop.Value != null ? prop.Value.ToString() : null;
        }

        // Очень простой разбор <Data Name="X">value</Data> из XML события (без загрузки XmlDocument).
        private static string XmlData(string xml, string name)
        {
            if (string.IsNullOrEmpty(xml)) return null;
            string open = "Name='" + name + "'>";
            int i = xml.IndexOf(open, StringComparison.Ordinal);
            if (i < 0)
            {
                open = "Name=\"" + name + "\">";
                i = xml.IndexOf(open, StringComparison.Ordinal);
                if (i < 0) return null;
            }
            i += open.Length;
            int j = xml.IndexOf("</Data>", i, StringComparison.Ordinal);
            if (j < 0) return null;
            return xml.Substring(i, j - i).Trim();
        }

        private void RaiseError(string message)
        {
            Action<string> handler = Error;
            if (handler != null) handler(message);
        }
    }
}
