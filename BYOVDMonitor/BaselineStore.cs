using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace BYOVDMonitor
{
    // Одна запись локальной базы папки: путь, размер, время изменения и хеш уже проверенного чистого файла.
    public class BaselineRecord
    {
        public string Path { get; set; }
        public long Size { get; set; }
        public long MtimeTicks { get; set; }
        public string Sha256 { get; set; }
    }

    // Файл локальной базы одной корневой папки.
    public class BaselineFile
    {
        public string RootPath { get; set; }
        public List<BaselineRecord> Entries { get; set; }
    }

    // Дополнительная локальная база на каждую наблюдаемую (корневую) папку.
    // Хранит хеши уже проверенных ЧИСТЫХ файлов, чтобы не перепроверять неизменённые файлы повторно.
    // Вредоносные файлы сюда не заносятся и всегда проверяются заново.
    public class BaselineStore
    {
        private readonly object _lock = new object();
        // rootPath -> (filePath -> запись)
        private readonly Dictionary<string, Dictionary<string, BaselineRecord>> _roots =
            new Dictionary<string, Dictionary<string, BaselineRecord>>(StringComparer.OrdinalIgnoreCase);

        private static string BaselineDir
        {
            get { return Path.Combine(AppConfig.DataDirectory, "baseline"); }
        }

        // Имя файла базы для корневой папки — по SHA-256 от пути (без недопустимых символов).
        private static string FileForRoot(string rootPath)
        {
            string key;
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(rootPath.ToLowerInvariant()));
                var sb = new StringBuilder(hash.Length * 2);
                for (int i = 0; i < hash.Length; i++) sb.Append(hash[i].ToString("X2"));
                key = sb.ToString();
            }
            return Path.Combine(BaselineDir, key + ".json");
        }

        // Загрузка базы корневой папки с диска в память.
        public void LoadRoot(string rootPath)
        {
            var map = new Dictionary<string, BaselineRecord>(StringComparer.OrdinalIgnoreCase);
            try
            {
                string file = FileForRoot(rootPath);
                if (File.Exists(file))
                {
                    BaselineFile data = Json.Deserialize<BaselineFile>(File.ReadAllText(file));
                    if (data != null && data.Entries != null)
                    {
                        foreach (BaselineRecord rec in data.Entries)
                        {
                            if (rec != null && !string.IsNullOrEmpty(rec.Path))
                                map[rec.Path] = rec;
                        }
                    }
                }
            }
            catch
            {
                // Повреждённая база папки не должна мешать работе — начнём с пустой.
            }
            lock (_lock) { _roots[rootPath] = map; }
        }

        // Файл не изменился относительно базы (тот же размер и время изменения) — можно пропустить без хеширования.
        public bool IsUnchanged(string rootPath, string filePath, long size, long mtimeTicks)
        {
            lock (_lock)
            {
                Dictionary<string, BaselineRecord> map;
                if (!_roots.TryGetValue(rootPath, out map)) return false;
                BaselineRecord rec;
                if (!map.TryGetValue(filePath, out rec)) return false;
                return rec.Size == size && rec.MtimeTicks == mtimeTicks;
            }
        }

        // Ранее сохранённый хеш файла (если есть).
        public string GetHash(string rootPath, string filePath)
        {
            lock (_lock)
            {
                Dictionary<string, BaselineRecord> map;
                if (!_roots.TryGetValue(rootPath, out map)) return null;
                BaselineRecord rec;
                if (!map.TryGetValue(filePath, out rec)) return null;
                return rec.Sha256;
            }
        }

        // Занести/обновить запись о чистом файле.
        public void Set(string rootPath, string filePath, long size, long mtimeTicks, string sha256)
        {
            lock (_lock)
            {
                Dictionary<string, BaselineRecord> map;
                if (!_roots.TryGetValue(rootPath, out map))
                {
                    map = new Dictionary<string, BaselineRecord>(StringComparer.OrdinalIgnoreCase);
                    _roots[rootPath] = map;
                }
                map[filePath] = new BaselineRecord
                {
                    Path = filePath,
                    Size = size,
                    MtimeTicks = mtimeTicks,
                    Sha256 = sha256
                };
            }
        }

        // Сохранение базы корневой папки на диск.
        public void SaveRoot(string rootPath)
        {
            try
            {
                BaselineFile data;
                lock (_lock)
                {
                    Dictionary<string, BaselineRecord> map;
                    if (!_roots.TryGetValue(rootPath, out map)) return;
                    data = new BaselineFile
                    {
                        RootPath = rootPath,
                        Entries = new List<BaselineRecord>(map.Values)
                    };
                }
                Directory.CreateDirectory(BaselineDir);
                File.WriteAllText(FileForRoot(rootPath), Json.Serialize(data));
            }
            catch
            {
                // Невозможность сохранить базу не критична.
            }
        }
    }
}
