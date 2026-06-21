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

            string sha256, sha1;
            if (!ComputeHashes(path, out sha256, out sha1)) return null;

            string driverName;
            if (_hashes.TryMatch(sha256, out driverName))
                return MakeDetection(path, sha256,
                    string.IsNullOrEmpty(driverName) ? "(имя неизвестно)" : driverName, "loldrivers");

            if (useMhr)
            {
                MhrResult r = _mhr.Lookup(sha1);
                if (r.Known)
                    return MakeDetection(path, sha256,
                        "Team Cymru MHR, детект " + r.DetectionRate + "%", "MHR");
            }

            return null;
        }

        private void AddWatcher(MonitoredFolder folder)
        {
            try
            {
                if (!Directory.Exists(folder.Path))
                {
                    RaiseError("Папка не найдена: " + folder.Path);
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
                RaiseError("Не удалось наблюдать за папкой " + folder.Path + ": " + ex.Message);
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
            RaiseError("Сбой наблюдателя: " + e.GetException().Message);
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
                RaiseError("Ошибка обхода " + folder.Path + ": " + ex.Message);
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

                string sha256, sha1;
                if (!ComputeHashes(path, out sha256, out sha1)) return;

                // Содержимое не изменилось (хеш совпал с локальным) — обновляем метку и пропускаем проверку.
                if (item.RootPath != null)
                {
                    string knownHash = _baseline.GetHash(item.RootPath, path);
                    if (knownHash != null && string.Equals(knownHash, sha256, StringComparison.OrdinalIgnoreCase))
                    {
                        _baseline.Set(item.RootPath, path, size, mtime, sha256);
                        return;
                    }
                }

                // Сверка с базой loldrivers.
                string driverName;
                if (_hashes.TryMatch(sha256, out driverName))
                {
                    RaiseDetectionDedup(path, sha256,
                        string.IsNullOrEmpty(driverName) ? "(имя неизвестно)" : driverName, "loldrivers");
                    return; // вредоносный — в локальную базу не заносим
                }

                // Дополнительная проверка новых файлов в MHR.
                if (item.FromWatcher && _config.MhrEnabled)
                {
                    ThrottleMhr();
                    MhrResult r = _mhr.Lookup(sha1);
                    if (r.Known)
                    {
                        RaiseDetectionDedup(path, sha256, "Team Cymru MHR, детект " + r.DetectionRate + "%", "MHR");
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
                    _baseline.Set(item.RootPath, path, size, mtime, sha256);
            }
            catch (Exception ex)
            {
                RaiseError("Ошибка обработки " + item.Path + ": " + ex.Message);
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

        // Подсчёт SHA-256 и SHA-1 за один проход чтения файла, с повторами при занятом файле.
        private static bool ComputeHashes(string path, out string sha256Hex, out string sha1Hex)
        {
            sha256Hex = null;
            sha1Hex = null;
            for (int attempt = 0; attempt < 4; attempt++)
            {
                try
                {
                    using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                               FileShare.ReadWrite | FileShare.Delete))
                    using (SHA256 sha256 = SHA256.Create())
                    using (SHA1 sha1 = SHA1.Create())
                    {
                        byte[] buffer = new byte[65536];
                        int read;
                        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            sha256.TransformBlock(buffer, 0, read, null, 0);
                            sha1.TransformBlock(buffer, 0, read, null, 0);
                        }
                        sha256.TransformFinalBlock(buffer, 0, 0);
                        sha1.TransformFinalBlock(buffer, 0, 0);
                        sha256Hex = ToHex(sha256.Hash);
                        sha1Hex = ToHex(sha1.Hash);
                        return true;
                    }
                }
                catch (IOException)
                {
                    Thread.Sleep(400);
                }
                catch (UnauthorizedAccessException)
                {
                    return false;
                }
            }
            return false;
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
