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

        // Уровень доверия к срабатыванию: "High" | "Medium" | "Low".
        // High  — точное совпадение содержимого (SHA-256) или подписанного тела (Authentihash),
        //         либо сам факт установки драйвера с таким содержимым.
        // Medium — внешний вердикт (MHR), относящийся к хешу, но не к конкретному драйверу.
        // Low   — эвристика: Imphash (отпечаток импортов часто общий у разных драйверов)
        //         или подозрительное состояние подписи (отзыв/недоверие).
        public string Confidence { get; set; }

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
