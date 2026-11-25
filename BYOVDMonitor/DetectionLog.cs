using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace BYOVDMonitor
{
    // Постоянный журнал срабатываний на диске: по одной JSON-записи на строку (JSONL).
    // Живой список в окне пропадает при перезагрузке — здесь срабатывания сохраняются,
    // и десктоп-версия подхватывает последние при запуске. Служба тоже пишет сюда
    // (помимо журнала событий Windows и webhook).
    //
    // Файл: %DataDirectory%\detections.jsonl (GUI — %APPDATA%, служба — %ProgramData%).
    internal static class DetectionLog
    {
        private static readonly object Lock = new object();

        private static string FilePath
        {
            get { return Path.Combine(AppConfig.DataDirectory, "detections.jsonl"); }
        }

        // Плоская запись строки журнала (для сериализации/разбора независимо от модели Detection).
        private class Row
        {
            public string time;        // ISO 8601 (UTC)
            public string file;
            public string sha256;
            public string match;
            public string confidence;
            public string source;
        }

        // Добавить одно срабатывание в конец файла. Ошибки записи не критичны.
        public static void Append(Detection d)
        {
            if (d == null) return;
            try
            {
                var row = new Row
                {
                    time = d.Time.ToUniversalTime().ToString("o"),
                    file = d.FilePath,
                    sha256 = d.Sha256,
                    match = d.DriverName,
                    confidence = d.Confidence,
                    source = d.Source
                };
                string line = Json.Serialize(row);

                lock (Lock)
                {
                    Directory.CreateDirectory(AppConfig.DataDirectory);
                    File.AppendAllText(FilePath, line + Environment.NewLine, new UTF8Encoding(false));
                }
            }
            catch
            {
                // Невозможность записать журнал не должна мешать обнаружению.
            }
        }

        // Загрузить последние max срабатываний, самые новые первыми (для заполнения списка в окне).
        public static List<Detection> LoadRecent(int max)
        {
            var result = new List<Detection>();
            try
            {
                lock (Lock)
                {
                    if (!File.Exists(FilePath)) return result;

                    string[] lines = File.ReadAllLines(FilePath);
                    int start = Math.Max(0, lines.Length - Math.Max(1, max));
                    for (int i = lines.Length - 1; i >= start; i--) // с конца — новые первыми
                    {
                        string line = lines[i];
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        Detection d = ParseLine(line);
                        if (d != null) result.Add(d);
                    }
                }
            }
            catch
            {
                // Повреждённый журнал не должен мешать запуску.
            }
            return result;
        }

        private static Detection ParseLine(string line)
        {
            try
            {
                Row row = Json.Deserialize<Row>(line);
                if (row == null) return null;

                DateTime time;
                if (!DateTime.TryParse(row.time, null,
                        System.Globalization.DateTimeStyles.RoundtripKind, out time))
                    time = DateTime.Now;

                return new Detection
                {
                    Time = time.ToLocalTime(),
                    FilePath = row.file,
                    Sha256 = row.sha256,
                    DriverName = row.match,
                    Confidence = row.confidence,
                    Source = row.source
                };
            }
            catch
            {
                return null;
            }
        }
    }
}
