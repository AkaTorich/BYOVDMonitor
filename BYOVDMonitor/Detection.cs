using System;

namespace BYOVDMonitor
{
    // Запись о найденном совпадении: файл, чей SHA-256 есть в базе уязвимых драйверов.
    public class Detection
    {
        public DateTime Time { get; set; }
        public string FilePath { get; set; }
        public string Sha256 { get; set; }
        public string DriverName { get; set; }
        public string Source { get; set; }  // источник совпадения: "loldrivers" или "MHR"

        // Время в удобном для отображения виде.
        public string TimeText
        {
            get { return Time.ToString("yyyy-MM-dd HH:mm:ss"); }
        }

        // Короткое имя файла для таблицы.
        public string FileName
        {
            get
            {
                try { return System.IO.Path.GetFileName(FilePath); }
                catch { return FilePath; }
            }
        }
    }
}
