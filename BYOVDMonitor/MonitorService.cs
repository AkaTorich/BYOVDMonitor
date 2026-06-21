using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace BYOVDMonitor
{
    // Единица работы: файл, признак "от наблюдателя" и корневая папка (для локальной базы).
    internal class WorkItem
    {
        public string Path;
        public bool FromWatcher;
        public string RootPath;
    }

    // Мониторинг настроенных папок: наблюдатель в реальном времени плюс обход существующих файлов.
    // Каждый файл хешируется (SHA-256) и сверяется с базой loldrivers; новые файлы (от наблюдателя)
    // при включённой опции дополнительно проверяются в Team Cymru MHR (по SHA-1, через DNS).
    // Неизменённые файлы пропускаются по локальной базе папки (baseline).
    public class MonitorService
    {
        private readonly HashListService _hashes;
        private readonly AppConfig _config;
        private readonly MhrService _mhr = new MhrService();
        private readonly BaselineStore _baseline = new BaselineStore();
        private readonly SynchronizationContext _uiContext;

        private readonly List<FileSystemWatcher> _watchers = new List<FileSystemWatcher>();
        private readonly HashSet<string> _alerted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly object _alertLock = new object();

        // Ограничение частоты запросов в MHR, чтобы не нагружать сервис.
        private readonly object _mhrLock = new object();
        private DateTime _lastMhr = DateTime.MinValue;
        private static readonly TimeSpan MhrMinInterval = TimeSpan.FromMilliseconds(250);

        private BlockingCollection<WorkItem> _queue;
        private Thread _worker;
        private List<MonitoredFolder> _currentFolders = new List<MonitoredFolder>();
        private volatile bool _running;

        // События вызываются в потоке пользовательского интерфейса.
        public event Action<Detection> Detected;
        public event Action<string> Error;

        public MonitorService(HashListService hashes, AppConfig config)
        {
            _hashes = hashes;
            _config = config;
            _uiContext = SynchronizationContext.Current;
        }

        public bool IsRunning { get { return _running; } }

        // Запуск мониторинга по списку папок.
        public void Start(IEnumerable<MonitoredFolder> folders)
        {
            Stop();

            _currentFolders = new List<MonitoredFolder>();
            if (folders != null) _currentFolders.AddRange(folders);

            _queue = new BlockingCollection<WorkItem>();
            _running = true;

            BlockingCollection<WorkItem> queue = _queue;
            _worker = new Thread(() => WorkerLoop(queue));
            _worker.IsBackground = true;
            _worker.Name = "byovd-hash-worker";
            _worker.Start();

            foreach (MonitoredFolder folder in _currentFolders)
            {
                if (folder == null || string.IsNullOrEmpty(folder.Path)) continue;
                _baseline.LoadRoot(folder.Path); // локальная база папки
                ScanFolder(folder);              // обход существующих файлов
                AddWatcher(folder);              // отслеживание новых
            }
        }

        // Остановка мониторинга, сохранение локальных баз и освобождение ресурсов.
        public void Stop()
        {
            _running = false;

            foreach (FileSystemWatcher watcher in _watchers)
            {
                try
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Dispose();
                }
                catch { }
            }
            _watchers.Clear();

            if (_queue != null)
            {
                try { _queue.CompleteAdding(); }
                catch { }
                _queue = null;
            }

            // Сохраняем локальные базы папок.
            foreach (MonitoredFolder folder in _currentFolders)
            {
                if (folder != null && !string.IsNullOrEmpty(folder.Path))
                    _baseline.SaveRoot(folder.Path);
            }
        }

        // Повторный обход всех папок (например, после обновления базы хешей).
        public void Rescan()
        {
            foreach (MonitoredFolder folder in _currentFolders)
            {
                if (folder == null || string.IsNullOrEmpty(folder.Path)) continue;
                ScanFolder(folder);
            }
        }

        // Ручная проверка одного файла: всегда проверяет (без учёта локальной базы).
        public Detection CheckFile(string path, bool useMhr)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;

            FileHashes hashes = ComputeAllHashes(path);
            if (hashes == null) return null;

            string matchSource, driverName;
            if (_hashes.TryMatch(hashes.Sha256, hashes.Imphash, hashes.Authentihash,
                                 out matchSource, out driverName))
            {
                return MakeDetection(path, hashes.Sha256,
                    string.IsNullOrEmpty(driverName) ? "(name unknown)" : driverName,
                    "loldrivers/" + matchSource);
            }

            if (useMhr && hashes.Sha1 != null)
            {
                MhrResult r = _mhr.Lookup(hashes.Sha1);
                if (r.Known)
                    return MakeDetection(path, hashes.Sha256,
                        "Team Cymru MHR, " + r.DetectionRate + "% detection", "MHR");
            }

            return null;
        }

        private void AddWatcher(MonitoredFolder folder)
        {
            try
            {
                if (!Directory.Exists(folder.Path))
                {
                    RaiseError("Folder not found: " + folder.Path);
                    return;
                }

                var watcher = new FileSystemWatcher(folder.Path);
                watcher.IncludeSubdirectories = folder.IncludeSubdirectories;
                watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size;
                watcher.InternalBufferSize = 64 * 1024;
                watcher.Filter = "*.*";

                watcher.Created += OnFileEvent;
                watcher.Changed += OnFileEvent;
                watcher.Renamed += OnFileRenamed;
                watcher.Error += OnWatcherError;

                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                RaiseError("Failed to watch folder " + folder.Path + ": " + ex.Message);
            }
        }

        private void OnFileEvent(object sender, FileSystemEventArgs e)
        {
            var watcher = sender as FileSystemWatcher;
            Enqueue(e.FullPath, true, watcher != null ? watcher.Path : null);
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            var watcher = sender as FileSystemWatcher;
            Enqueue(e.FullPath, true, watcher != null ? watcher.Path : null);
        }

        private void OnWatcherError(object sender, ErrorEventArgs e)
        {
            RaiseError("Watcher error: " + e.GetException().Message);
        }

        private void Enqueue(string path, bool fromWatcher, string rootPath)
        {
            BlockingCollection<WorkItem> queue = _queue;
            if (queue == null) return;
            try { queue.Add(new WorkItem { Path = path, FromWatcher = fromWatcher, RootPath = rootPath }); }
            catch { } // очередь закрыта при остановке
        }

        private void ScanFolder(MonitoredFolder folder)
        {
            try
            {
                foreach (string file in SafeEnumerateFiles(folder.Path, folder.IncludeSubdirectories))
                    Enqueue(file, false, folder.Path);
            }
            catch (Exception ex)
            {
                RaiseError("Scan error in " + folder.Path + ": " + ex.Message);
            }
        }

        // Безопасный обход с пропуском недоступных вложенных папок.
        private IEnumerable<string> SafeEnumerateFiles(string root, bool recursive)
        {
            var pending = new Stack<string>();
            pending.Push(root);

            while (pending.Count > 0)
            {
                string dir = pending.Pop();

                string[] files = null;
                try { files = Directory.GetFiles(dir); }
                catch { files = null; }

                if (files != null)
                {
                    foreach (string file in files)
                        yield return file;
                }

                if (!recursive) continue;

                string[] subdirs = null;
                try { subdirs = Directory.GetDirectories(dir); }
                catch { subdirs = null; }

                if (subdirs != null)
                {
                    foreach (string sub in subdirs)
                        pending.Push(sub);
                }
            }
        }

        private void WorkerLoop(BlockingCollection<WorkItem> queue)
        {
            try
            {
                foreach (WorkItem item in queue.GetConsumingEnumerable())
                {
                    if (!_running) break;
                    ProcessFile(item);
                }
            }
            catch (ObjectDisposedException) { }
            catch (InvalidOperationException) { }
        }

        private void ProcessFile(WorkItem item)
        {
            try
            {
                string path = item.Path;
                if (!File.Exists(path)) return;

                if (!_config.IncludeAllExtensions)
                {
                    string ext = Path.GetExtension(path);
                    if (!string.Equals(ext, ".sys", StringComparison.OrdinalIgnoreCase)) return;
                }

                var info = new FileInfo(path);
                long maxBytes = (long)_config.MaxFileSizeMb * 1024 * 1024;
                if (info.Length > maxBytes || info.Length == 0) return;

                long size = info.Length;
                long mtime = info.LastWriteTimeUtc.Ticks;

                // Файл не менялся с прошлой проверки (по локальной базе папки) — пропускаем без хеширования.
                if (item.RootPath != null && _baseline.IsUnchanged(item.RootPath, path, size, mtime))
                    return;

                // Дешёвая отсечка: если это вообще не PE-образ (драйвер/EXE/DLL/OCX/EFI),
                // не имеет смысла его хешировать — заведомо нет в базе уязвимых драйверов.
                if (!PeProbe.IsPortableExecutable(path))
                    return;

                FileHashes hashes = ComputeAllHashes(path);
                if (hashes == null) return;

                // Содержимое не изменилось (SHA-256 совпал с локальным) — обновляем метку и выходим.
                if (item.RootPath != null)
                {
                    string knownHash = _baseline.GetHash(item.RootPath, path);
                    if (knownHash != null && string.Equals(knownHash, hashes.Sha256, StringComparison.OrdinalIgnoreCase))
                    {
                        _baseline.Set(item.RootPath, path, size, mtime, hashes.Sha256);
                        return;
                    }
                }

                // Сверка с базой loldrivers по трём хешам сразу.
                string matchSource, driverName;
                if (_hashes.TryMatch(hashes.Sha256, hashes.Imphash, hashes.Authentihash,
                                     out matchSource, out driverName))
                {
                    RaiseDetectionDedup(path, hashes.Sha256,
                        string.IsNullOrEmpty(driverName) ? "(name unknown)" : driverName,
                        "loldrivers/" + matchSource);
                    return; // вредоносный — в локальную базу не заносим
                }

                // Дополнительная проверка новых файлов в MHR (по SHA-1).
                if (item.FromWatcher && _config.MhrEnabled && hashes.Sha1 != null)
                {
                    ThrottleMhr();
                    MhrResult r = _mhr.Lookup(hashes.Sha1);
                    if (r.Known)
                    {
                        RaiseDetectionDedup(path, hashes.Sha256,
                            "Team Cymru MHR, " + r.DetectionRate + "% detection", "MHR");
                        return;
                    }
                    if (r.Error != null)
                    {
                        // Сеть недоступна — не заносим как чистый, перепроверим позже.
                        return;
                    }
                }

                // Чистый файл — заносим в локальную базу папки, чтобы не перепроверять повторно.
                if (item.RootPath != null)
                    _baseline.Set(item.RootPath, path, size, mtime, hashes.Sha256);
            }
            catch (Exception ex)
            {
                RaiseError("Failed to process " + item.Path + ": " + ex.Message);
            }
        }

        private void ThrottleMhr()
        {
            lock (_mhrLock)
            {
                TimeSpan since = DateTime.UtcNow - _lastMhr;
                if (since < MhrMinInterval)
                    Thread.Sleep(MhrMinInterval - since);
                _lastMhr = DateTime.UtcNow;
            }
        }

        // Все хеши файла, посчитанные за одно чтение.
        private class FileHashes
        {
            public string Sha256;
            public string Sha1;
            public string Imphash;       // может быть null, если не удалось разобрать PE
            public string Authentihash;  // может быть null, если не удалось разобрать PE
        }

        // Чтение файла целиком + подсчёт всех хешей (SHA-256, SHA-1, Imphash, Authentihash).
        // Драйверы маленькие; MaxFileSizeMb уже ограничивает входной размер. Чтение в памяти —
        // быстрее, чем многопроходный стрим, и даёт PeAnalyzer прямой доступ к байтам.
        private static FileHashes ComputeAllHashes(string path)
        {
            byte[] bytes = null;
            for (int attempt = 0; attempt < 4; attempt++)
            {
                try
                {
                    using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                               FileShare.ReadWrite | FileShare.Delete))
                    {
                        long len = stream.Length;
                        if (len <= 0 || len > int.MaxValue) return null;
                        bytes = new byte[len];
                        int read = 0;
                        while (read < bytes.Length)
                        {
                            int n = stream.Read(bytes, read, bytes.Length - read);
                            if (n <= 0) break;
                            read += n;
                        }
                        if (read != bytes.Length) bytes = null;
                    }
                    if (bytes != null) break;
                }
                catch (IOException)
                {
                    Thread.Sleep(400);
                }
                catch (UnauthorizedAccessException)
                {
                    return null;
                }
            }
            if (bytes == null) return null;

            var result = new FileHashes();
            using (SHA256 sha256 = SHA256.Create())
                result.Sha256 = ToHex(sha256.ComputeHash(bytes));
            using (SHA1 sha1 = SHA1.Create())
                result.Sha1 = ToHex(sha1.ComputeHash(bytes));

            // Imphash и Authentihash могут не получиться (повреждённый PE) — это не ошибка.
            result.Imphash = PeAnalyzer.ComputeImphash(bytes);
            result.Authentihash = PeAnalyzer.ComputeAuthentihash(bytes);

            return result;
        }

        private static string ToHex(byte[] bytes)
        {
            var builder = new StringBuilder(bytes.Length * 2);
            for (int i = 0; i < bytes.Length; i++)
                builder.Append(bytes[i].ToString("X2"));
            return builder.ToString();
        }

        private static Detection MakeDetection(string path, string sha256, string name, string source)
        {
            return new Detection
            {
                Time = DateTime.Now,
                FilePath = path,
                Sha256 = sha256,
                DriverName = name,
                Source = source
            };
        }

        private void RaiseDetectionDedup(string path, string sha256, string name, string source)
        {
            string key = path.ToUpperInvariant() + "|" + sha256 + "|" + source;
            lock (_alertLock)
            {
                if (_alerted.Contains(key)) return;
                _alerted.Add(key);
            }
            RaiseDetected(MakeDetection(path, sha256, name, source));
        }

        private void RaiseDetected(Detection detection)
        {
            Action<Detection> handler = Detected;
            if (handler == null) return;
            if (_uiContext != null)
                _uiContext.Post(state => handler(detection), null);
            else
                handler(detection);
        }

        private void RaiseError(string message)
        {
            Action<string> handler = Error;
            if (handler == null) return;
            if (_uiContext != null)
                _uiContext.Post(state => handler(message), null);
            else
                handler(message);
        }
    }
}
