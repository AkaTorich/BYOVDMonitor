using System;
using System.Collections.Generic;
using System.IO;

namespace BYOVDMonitor
{
    // Одна наблюдаемая папка и признак рекурсивного обхода вложенных папок.
    public class MonitoredFolder
    {
        public string Path { get; set; }
        public bool IncludeSubdirectories { get; set; }
    }

    // Настройки приложения. Хранятся в %APPDATA%\BYOVDMonitor\config.json.
    public class AppConfig
    {
        public List<MonitoredFolder> Folders { get; set; }
        public bool SoundEnabled { get; set; }
        public string HashListUrl { get; set; }
        public int MaxFileSizeMb { get; set; }
        public bool IncludeAllExtensions { get; set; }
        public int RescanIntervalMinutes { get; set; }
        public bool MhrEnabled { get; set; }     // проверять новые файлы в Team Cymru MHR (DNS)
        public string WebhookUrl { get; set; }   // адрес для отправки оповещений в SIEM (HTTP POST JSON); пусто = выкл
        public int FullRescanIntervalHours { get; set; } // 0 = выключен; иначе раз в N часов глубокий обход с пересчётом всех хешей (игнорирует baseline)
        public bool DriverLoadWatchEnabled { get; set; }  // следить за установкой драйверов через журнал событий (7045/4697) — ловит BYOVD по любому пути
        public bool SignatureCheckEnabled { get; set; }   // помечать установленные драйверы с отозванной/недоверенной подписью (эвристика, низкое доверие)

        public AppConfig()
        {
            // Значения по умолчанию для первого запуска.
            Folders = DefaultFolders();
            SoundEnabled = true;
            HashListUrl = "https://www.loldrivers.io/api/drivers.json";
            MaxFileSizeMb = 64;          // драйверы маленькие, большие файлы пропускаем
            IncludeAllExtensions = true; // уязвимый драйвер могут положить под любым именем
            RescanIntervalMinutes = 15;  // фоновый повторный обход как страховка
            FullRescanIntervalHours = 24; // раз в сутки глубокий обход (защита от подмены с восстановлением timestamps)
            DriverLoadWatchEnabled = true; // ловить саму установку драйвера (журнал событий), не только файл в папке
            SignatureCheckEnabled = true;  // проверять подпись установленных драйверов на отзыв/недоверие
        }

        // Папки, с которых разумно начать на первом запуске: системные драйверы и временный каталог —
        // типичные места появления уязвимого драйвера. Пользователь затем правит список в окне/конфиге.
        private static List<MonitoredFolder> DefaultFolders()
        {
            var list = new List<MonitoredFolder>();
            try
            {
                string drivers = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers");
                if (Directory.Exists(drivers))
                    list.Add(new MonitoredFolder { Path = drivers, IncludeSubdirectories = false });

                string temp = Path.GetTempPath();
                if (!string.IsNullOrEmpty(temp))
                {
                    temp = temp.TrimEnd('\\');
                    if (Directory.Exists(temp))
                        list.Add(new MonitoredFolder { Path = temp, IncludeSubdirectories = true });
                }
            }
            catch
            {
                // Не удалось определить системные пути — остаёмся с пустым списком.
            }
            return list;
        }

        // Каталог данных приложения. По умолчанию — %APPDATA%\BYOVDMonitor (для GUI).
        // Служба переопределяет значение на %ProgramData%\BYOVDMonitor до первого обращения.
        private static string _dataDirectory;
        public static string DataDirectory
        {
            get
            {
                if (_dataDirectory == null)
                {
                    string baseDir = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                    _dataDirectory = System.IO.Path.Combine(baseDir, "BYOVDMonitor");
                }
                return _dataDirectory;
            }
            set { _dataDirectory = value; }
        }

        private static string ConfigPath
        {
            get { return System.IO.Path.Combine(DataDirectory, "config.json"); }
        }

        // Загрузка настроек; при отсутствии или ошибке возвращаются значения по умолчанию.
        public static AppConfig Load()
        {
            try
            {
                if (File.Exists(ConfigPath))
                {
                    string json = File.ReadAllText(ConfigPath);
                    AppConfig config = Json.Deserialize<AppConfig>(json);
                    if (config != null)
                    {
                        if (config.Folders == null) config.Folders = new List<MonitoredFolder>();
                        if (string.IsNullOrEmpty(config.HashListUrl))
                            config.HashListUrl = "https://www.loldrivers.io/api/drivers.json";
                        if (config.MaxFileSizeMb <= 0) config.MaxFileSizeMb = 64;
                        if (config.RescanIntervalMinutes <= 0) config.RescanIntervalMinutes = 15;
                        return config;
                    }
                }
            }
            catch
            {
                // Повреждённый файл настроек не должен мешать запуску.
            }
            return new AppConfig();
        }

        // Сохранение настроек.
        public void Save()
        {
            try
            {
                Directory.CreateDirectory(DataDirectory);
                File.WriteAllText(ConfigPath, Json.Serialize(this));
            }
            catch
            {
                // Невозможность записать настройки не критична для работы.
            }
        }
    }
}
