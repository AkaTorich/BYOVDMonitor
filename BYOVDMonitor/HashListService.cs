using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace BYOVDMonitor
{
    // Одна запись локального хранилища: хеш и понятное имя драйвера.
    public class HashEntry
    {
        public string Sha256 { get; set; }
        public string Name { get; set; }
    }

    // Структура файла локального хранилища базы хешей.
    public class HashStore
    {
        public string SourceUrl { get; set; }
        public string DownloadedUtc { get; set; }
        public string ContentSha256 { get; set; } // хеш самого скачанного JSON для определения изменений
        public string ETag { get; set; }
        public int Count { get; set; }
        public List<HashEntry> Items { get; set; }
    }

    // Результат проверки обновлений. Если есть новое — внутри уже разобранная база, готовая к применению.
    public class UpdateCheckResult
    {
        public bool UpdateAvailable { get; set; }
        public int NewCount { get; set; }
        public string Error { get; set; }

        // Подготовленные данные для применения (заполняются только если UpdateAvailable).
        internal Dictionary<string, string> Map { get; set; }
        internal string ContentSha256 { get; set; }
        internal string ETag { get; set; }
        internal string SourceUrl { get; set; }
    }

    // Сервис базы известных уязвимых драйверов: скачивание, разбор, хранение, проверка обновлений и сверка.
    public class HashListService
    {
        // Текущая карта: SHA-256 (верхний регистр) -> имя драйвера. Меняется атомарно через присваивание ссылки.
        private volatile Dictionary<string, string> _map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static readonly HttpClient Http = CreateHttpClient();

        public int Count { get; private set; }
        public DateTime? LastUpdatedUtc { get; private set; }
        public bool HasLocalList { get; private set; }

        private static string StorePath
        {
            get { return Path.Combine(AppConfig.DataDirectory, "hashes.json"); }
        }

        private static HttpClient CreateHttpClient()
        {
            // loldrivers.io работает по HTTPS, на .NET Framework нужно явно включить TLS 1.2.
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            var client = new HttpClient();
            client.Timeout = TimeSpan.FromSeconds(120); // база большая (~30 МБ)
            client.DefaultRequestHeaders.UserAgent.ParseAdd("BYOVDMonitor/1.0");
            return client;
        }

        // Проверка совпадения хеша файла с базой.
        public bool TryMatch(string sha256Upper, out string driverName)
        {
            return _map.TryGetValue(sha256Upper, out driverName);
        }

        // Загрузка ранее сохранённой базы с диска.
        public void Load()
        {
            try
            {
                if (!File.Exists(StorePath))
                {
                    HasLocalList = false;
                    return;
                }

                string json = File.ReadAllText(StorePath);
                HashStore store = Json.Deserialize<HashStore>(json);
                if (store == null || store.Items == null)
                {
                    HasLocalList = false;
                    return;
                }

                var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (HashEntry entry in store.Items)
                {
                    if (entry != null && IsSha256(entry.Sha256))
                        map[entry.Sha256.ToUpperInvariant()] = entry.Name ?? string.Empty;
                }

                _map = map;
                Count = map.Count;
                HasLocalList = map.Count > 0;
                DateTime parsed;
                if (DateTime.TryParse(store.DownloadedUtc, out parsed))
                    LastUpdatedUtc = parsed;
            }
            catch
            {
                HasLocalList = false;
            }
        }

        // Принудительное скачивание базы и немедленное применение.
        public async Task<int> DownloadAndApplyAsync(string url)
        {
            using (HttpResponseMessage response = await Http.GetAsync(url).ConfigureAwait(false))
            {
                response.EnsureSuccessStatusCode();
                byte[] data = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                string json = Encoding.UTF8.GetString(data);
                string contentHash = Sha256Hex(data);
                string etag = response.Headers.ETag != null ? response.Headers.ETag.Tag : null;

                Dictionary<string, string> map = ParseHashes(json);
                ApplyMap(map, contentHash, etag, url);
                return map.Count;
            }
        }

        // Проверка обновлений: условный запрос по ETag, при изменении содержимого — разбор новой базы.
        public async Task<UpdateCheckResult> CheckForUpdateAsync(string url)
        {
            var result = new UpdateCheckResult();
            try
            {
                string knownEtag = ReadStoredEtag();
                string knownContentHash = ReadStoredContentHash();

                using (var request = new HttpRequestMessage(HttpMethod.Get, url))
                {
                    if (!string.IsNullOrEmpty(knownEtag))
                        request.Headers.TryAddWithoutValidation("If-None-Match", knownEtag);

                    using (HttpResponseMessage response = await Http.SendAsync(request).ConfigureAwait(false))
                    {
                        if (response.StatusCode == HttpStatusCode.NotModified)
                        {
                            result.UpdateAvailable = false;
                            return result;
                        }

                        response.EnsureSuccessStatusCode();
                        byte[] data = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                        string contentHash = Sha256Hex(data);

                        // Сервер может не поддерживать ETag — сравниваем по хешу содержимого.
                        if (!string.IsNullOrEmpty(knownContentHash) &&
                            string.Equals(knownContentHash, contentHash, StringComparison.OrdinalIgnoreCase))
                        {
                            result.UpdateAvailable = false;
                            return result;
                        }

                        string json = Encoding.UTF8.GetString(data);
                        Dictionary<string, string> map = ParseHashes(json);

                        result.UpdateAvailable = true;
                        result.NewCount = map.Count;
                        result.Map = map;
                        result.ContentSha256 = contentHash;
                        result.SourceUrl = url;
                        if (response.Headers.ETag != null)
                            result.ETag = response.Headers.ETag.Tag;
                        return result;
                    }
                }
            }
            catch (Exception ex)
            {
                result.UpdateAvailable = false;
                result.Error = ex.Message;
                return result;
            }
        }

        // Применение ранее найденного обновления (без повторного скачивания).
        public void ApplyUpdate(UpdateCheckResult result)
        {
            if (result == null || result.Map == null) return;
            ApplyMap(result.Map, result.ContentSha256, result.ETag, result.SourceUrl);
        }

        // Запись новой карты в память и на диск.
        private void ApplyMap(Dictionary<string, string> map, string contentHash, string etag, string url)
        {
            var store = new HashStore();
            store.SourceUrl = url;
            store.DownloadedUtc = DateTime.UtcNow.ToString("o");
            store.ContentSha256 = contentHash;
            store.ETag = etag;
            store.Count = map.Count;
            store.Items = new List<HashEntry>(map.Count);
            foreach (KeyValuePair<string, string> pair in map)
                store.Items.Add(new HashEntry { Sha256 = pair.Key, Name = pair.Value });

            Directory.CreateDirectory(AppConfig.DataDirectory);
            File.WriteAllText(StorePath, Json.Serialize(store));

            _map = map;
            Count = map.Count;
            HasLocalList = map.Count > 0;
            LastUpdatedUtc = DateTime.UtcNow;
        }

        private static string ReadStoredEtag()
        {
            try
            {
                if (!File.Exists(StorePath)) return null;
                HashStore store = Json.Deserialize<HashStore>(File.ReadAllText(StorePath));
                return store != null ? store.ETag : null;
            }
            catch { return null; }
        }

        private static string ReadStoredContentHash()
        {
            try
            {
                if (!File.Exists(StorePath)) return null;
                HashStore store = Json.Deserialize<HashStore>(File.ReadAllText(StorePath));
                return store != null ? store.ContentSha256 : null;
            }
            catch { return null; }
        }

        // Разбор JSON loldrivers: вытаскиваем SHA-256 образцов и понятное имя драйвера.
        // Структура устойчиво обрабатывается: сначала ищем сущности с KnownVulnerableSamples,
        // затем общим проходом подбираем оставшиеся SHA-256.
        private static Dictionary<string, string> ParseHashes(string json)
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            object root = Json.DeserializeObject(json);
            Collect(root, map);
            return map;
        }

        private static void Collect(object node, Dictionary<string, string> map)
        {
            object[] array = node as object[];
            if (array != null)
            {
                foreach (object element in array)
                    Collect(element, map);
                return;
            }

            var dict = node as Dictionary<string, object>;
            if (dict == null) return;

            // Если это запись о драйвере с образцами — извлекаем имена вместе с хешами.
            object samplesObj;
            if (dict.TryGetValue("KnownVulnerableSamples", out samplesObj))
            {
                object[] samples = samplesObj as object[];
                if (samples != null)
                {
                    string driverName = DriverDisplayName(dict);
                    foreach (object sampleObj in samples)
                    {
                        var sample = sampleObj as Dictionary<string, object>;
                        if (sample == null) continue;

                        string sha = GetString(sample, "SHA256");
                        if (!IsSha256(sha)) continue;

                        string fileName = GetString(sample, "Filename");
                        string display = !string.IsNullOrEmpty(fileName)
                            ? (string.IsNullOrEmpty(driverName) ? fileName : driverName + " (" + fileName + ")")
                            : driverName;

                        map[sha.ToUpperInvariant()] = display ?? string.Empty;
                    }
                }
            }

            // Общий проход: ловим SHA-256 в любых других местах, не затирая уже найденные имена.
            foreach (KeyValuePair<string, object> pair in dict)
            {
                if (string.Equals(pair.Key, "SHA256", StringComparison.OrdinalIgnoreCase))
                {
                    string sha = pair.Value as string;
                    if (IsSha256(sha) && !map.ContainsKey(sha.ToUpperInvariant()))
                        map[sha.ToUpperInvariant()] = string.Empty;
                }
                Collect(pair.Value, map);
            }
        }

        // Подбор понятного имени драйвера из записи loldrivers.
        private static string DriverDisplayName(Dictionary<string, object> driver)
        {
            object tagsObj;
            if (driver.TryGetValue("Tags", out tagsObj))
            {
                object[] tags = tagsObj as object[];
                if (tags != null && tags.Length > 0)
                {
                    string first = tags[0] as string;
                    if (!string.IsNullOrEmpty(first)) return first;
                }
            }

            string category = GetString(driver, "Category");
            if (!string.IsNullOrEmpty(category)) return category;

            string id = GetString(driver, "Id");
            if (!string.IsNullOrEmpty(id)) return id;

            return string.Empty;
        }

        private static string GetString(Dictionary<string, object> dict, string key)
        {
            object value;
            if (dict.TryGetValue(key, out value))
                return value as string;
            return null;
        }

        // Проверка, что строка похожа на SHA-256 (64 шестнадцатеричных символа).
        private static bool IsSha256(string value)
        {
            if (value == null || value.Length != 64) return false;
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!hex) return false;
            }
            return true;
        }

        private static string Sha256Hex(byte[] data)
        {
            using (SHA256 sha = SHA256.Create())
                return ToHex(sha.ComputeHash(data));
        }

        private static string ToHex(byte[] bytes)
        {
            var builder = new StringBuilder(bytes.Length * 2);
            for (int i = 0; i < bytes.Length; i++)
                builder.Append(bytes[i].ToString("X2"));
            return builder.ToString();
        }
    }
}
