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

        public AppConfig()
        {
            // Значения по умолчанию для первого запуска.
            Folders = new List<MonitoredFolder>();
            SoundEnabled = true;
            HashListUrl = "https://www.loldrivers.io/api/drivers.json";
            MaxFileSizeMb = 64;          // драйверы маленькие, большие файлы пропускаем
            IncludeAllExtensions = true; // уязвимый драйвер могут положить под любым именем
            RescanIntervalMinutes = 15;  // фоновый повторный обход как страховка
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
