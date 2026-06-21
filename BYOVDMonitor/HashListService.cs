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
    // Одна запись локального хранилища: набор хешей одного известного образца и понятное имя.
    public class HashEntry
    {
        public string Sha256 { get; set; }
        public string Imphash { get; set; }
        public string Authentihash { get; set; }
        public string Name { get; set; }
    }

    // Структура файла локального хранилища базы хешей.
    public class HashStore
    {
        public int SchemaVersion { get; set; }           // 0/1 — старый формат (только Sha256), 2+ — есть Imphash/Authentihash
        public string SourceUrl { get; set; }
        public string DownloadedUtc { get; set; }
        public string ContentSha256 { get; set; }
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

        internal List<HashEntry> Entries { get; set; }
        internal string ContentSha256 { get; set; }
        internal string ETag { get; set; }
        internal string SourceUrl { get; set; }
    }

    // Сервис базы известных уязвимых драйверов: скачивание, разбор, хранение, проверка обновлений и сверка.
    // Поддерживает совпадение по любому из трёх хешей: SHA-256, Imphash, Authentihash.
    public class HashListService
    {
        public const int CurrentSchemaVersion = 2;

        // Текущие карты: HEX (верхний регистр) -> запись. Меняются атомарно через присваивание ссылки.
        private volatile Dictionary<string, HashEntry> _bySha256 =
            new Dictionary<string, HashEntry>(StringComparer.OrdinalIgnoreCase);
        private volatile Dictionary<string, HashEntry> _byImphash =
            new Dictionary<string, HashEntry>(StringComparer.OrdinalIgnoreCase);
        private volatile Dictionary<string, HashEntry> _byAuthentihash =
            new Dictionary<string, HashEntry>(StringComparer.OrdinalIgnoreCase);

        private static readonly HttpClient Http = CreateHttpClient();

        public int Count { get { return _bySha256.Count; } }
        public int ImphashCount { get { return _byImphash.Count; } }
        public int AuthentihashCount { get { return _byAuthentihash.Count; } }
        public DateTime? LastUpdatedUtc { get; private set; }
        public bool HasLocalList { get; private set; }
        // true, если на диске лежит база старого формата без Imphash/Authentihash — нужен полный
        // повторный скачок (приложение должно сделать его без диалога).
        public bool NeedsFreshDownload { get; private set; }

        private static string StorePath
        {
            get { return Path.Combine(AppConfig.DataDirectory, "hashes.json"); }
        }

        private static HttpClient CreateHttpClient()
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            var client = new HttpClient();
            client.Timeout = TimeSpan.FromSeconds(120);
            client.DefaultRequestHeaders.UserAgent.ParseAdd("BYOVDMonitor/1.3");
            return client;
        }

        // Проверка по трём хешам. Возвращает true и заполняет matchSource/name при первом совпадении.
        // matchSource: "sha256" | "imphash" | "authentihash".
        public bool TryMatch(string sha256Upper, string imphashUpper, string authentihashUpper,
                             out string matchSource, out string name)
        {
            HashEntry entry;
            if (!string.IsNullOrEmpty(sha256Upper) && _bySha256.TryGetValue(sha256Upper, out entry))
            {
                matchSource = "sha256";
                name = entry.Name ?? string.Empty;
                return true;
            }
            if (!string.IsNullOrEmpty(imphashUpper) && _byImphash.TryGetValue(imphashUpper, out entry))
            {
                matchSource = "imphash";
                name = entry.Name ?? string.Empty;
                return true;
            }
            if (!string.IsNullOrEmpty(authentihashUpper) && _byAuthentihash.TryGetValue(authentihashUpper, out entry))
            {
                matchSource = "authentihash";
                name = entry.Name ?? string.Empty;
                return true;
            }
            matchSource = null;
            name = null;
            return false;
        }

        // Загрузка ранее сохранённой базы с диска. Если схема старая — отметит NeedsFreshDownload.
        public void Load()
        {
            try
            {
                if (!File.Exists(StorePath))
                {
                    HasLocalList = false;
                    NeedsFreshDownload = false;
                    return;
                }

                string json = File.ReadAllText(StorePath);
                HashStore store = Json.Deserialize<HashStore>(json);
                if (store == null || store.Items == null)
                {
                    HasLocalList = false;
                    return;
                }

                var bySha256 = new Dictionary<string, HashEntry>(StringComparer.OrdinalIgnoreCase);
                var byImphash = new Dictionary<string, HashEntry>(StringComparer.OrdinalIgnoreCase);
                var byAuthen = new Dictionary<string, HashEntry>(StringComparer.OrdinalIgnoreCase);

                foreach (HashEntry e in store.Items)
                {
                    if (e == null) continue;
                    if (IsHex(e.Sha256, 64))
                        bySha256[e.Sha256.ToUpperInvariant()] = e;
                    if (IsHex(e.Imphash, 32))
                        byImphash[e.Imphash.ToUpperInvariant()] = e;
                    if (IsHex(e.Authentihash, 64))
                        byAuthen[e.Authentihash.ToUpperInvariant()] = e;
                }

                _bySha256 = bySha256;
                _byImphash = byImphash;
                _byAuthentihash = byAuthen;

                HasLocalList = bySha256.Count > 0;
                // Старый формат — нет ни одного Imphash/Authentihash при ненулевой базе → надо обновить.
                NeedsFreshDownload = HasLocalList && store.SchemaVersion < CurrentSchemaVersion;

                DateTime parsed;
                if (DateTime.TryParse(store.DownloadedUtc, out parsed))
                    LastUpdatedUtc = parsed;
            }
            catch
            {
                HasLocalList = false;
                NeedsFreshDownload = false;
            }
        }

        // Принудительное скачивание базы и немедленное применение (используется при отсутствии
        // локальной базы или при апгрейде схемы — без учёта ETag).
        public async Task<int> DownloadAndApplyAsync(string url)
        {
            using (HttpResponseMessage response = await Http.GetAsync(url).ConfigureAwait(false))
            {
                response.EnsureSuccessStatusCode();
                byte[] data = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                string json = Encoding.UTF8.GetString(data);
                string contentHash = Sha256Hex(data);
                string etag = response.Headers.ETag != null ? response.Headers.ETag.Tag : null;

                List<HashEntry> entries = ParseEntries(json);
                ApplyEntries(entries, contentHash, etag, url);
                return _bySha256.Count;
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

                        if (!string.IsNullOrEmpty(knownContentHash) &&
                            string.Equals(knownContentHash, contentHash, StringComparison.OrdinalIgnoreCase))
                        {
                            result.UpdateAvailable = false;
                            return result;
                        }

                        string json = Encoding.UTF8.GetString(data);
                        List<HashEntry> entries = ParseEntries(json);

                        result.UpdateAvailable = true;
                        result.NewCount = entries.Count;
                        result.Entries = entries;
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
            if (result == null || result.Entries == null) return;
            ApplyEntries(result.Entries, result.ContentSha256, result.ETag, result.SourceUrl);
        }

        // Запись новой базы в память и на диск.
        private void ApplyEntries(List<HashEntry> entries, string contentHash, string etag, string url)
        {
            var bySha256 = new Dictionary<string, HashEntry>(StringComparer.OrdinalIgnoreCase);
            var byImphash = new Dictionary<string, HashEntry>(StringComparer.OrdinalIgnoreCase);
            var byAuthen = new Dictionary<string, HashEntry>(StringComparer.OrdinalIgnoreCase);

            foreach (HashEntry e in entries)
            {
                if (e == null) continue;
                if (IsHex(e.Sha256, 64))
                    bySha256[e.Sha256.ToUpperInvariant()] = e;
                if (IsHex(e.Imphash, 32))
                    byImphash[e.Imphash.ToUpperInvariant()] = e;
                if (IsHex(e.Authentihash, 64))
                    byAuthen[e.Authentihash.ToUpperInvariant()] = e;
            }

            var store = new HashStore
            {
                SchemaVersion = CurrentSchemaVersion,
                SourceUrl = url,
                DownloadedUtc = DateTime.UtcNow.ToString("o"),
                ContentSha256 = contentHash,
                ETag = etag,
                Count = bySha256.Count,
                Items = entries
            };

            Directory.CreateDirectory(AppConfig.DataDirectory);
            File.WriteAllText(StorePath, Json.Serialize(store));

            _bySha256 = bySha256;
            _byImphash = byImphash;
            _byAuthentihash = byAuthen;
            HasLocalList = bySha256.Count > 0;
            NeedsFreshDownload = false;
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

        // Разбор JSON loldrivers: вытаскиваем по каждому образцу SHA-256, Imphash, Authentihash и имя.
        // Дедуплицируем по SHA-256: если такой уже встречался, дополняем недостающие поля.
        private static List<HashEntry> ParseEntries(string json)
        {
            var bySha256 = new Dictionary<string, HashEntry>(StringComparer.OrdinalIgnoreCase);
            object root = Json.DeserializeObject(json);
            Collect(root, bySha256);
            return new List<HashEntry>(bySha256.Values);
        }

        private static void Collect(object node, Dictionary<string, HashEntry> bySha256)
        {
            object[] array = node as object[];
            if (array != null)
            {
                foreach (object element in array)
                    Collect(element, bySha256);
                return;
            }

            var dict = node as Dictionary<string, object>;
            if (dict == null) return;

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
                        if (!IsHex(sha, 64)) continue;
                        string shaKey = sha.ToUpperInvariant();

                        string filename = GetString(sample, "Filename");
                        string display = !string.IsNullOrEmpty(filename)
                            ? (string.IsNullOrEmpty(driverName) ? filename : driverName + " (" + filename + ")")
                            : driverName;

                        HashEntry entry;
                        if (!bySha256.TryGetValue(shaKey, out entry))
                        {
                            entry = new HashEntry { Sha256 = shaKey };
                            bySha256[shaKey] = entry;
                        }
                        if (string.IsNullOrEmpty(entry.Name) && !string.IsNullOrEmpty(display))
                            entry.Name = display;

                        string imph = GetString(sample, "Imphash");
                        if (IsHex(imph, 32) && string.IsNullOrEmpty(entry.Imphash))
                            entry.Imphash = imph.ToUpperInvariant();

                        // Authentihash в loldrivers — вложенный словарь {MD5, SHA1, SHA256}.
                        // Берём SHA-256 (мой ComputeAuthentihash тоже SHA-256).
                        string auth = GetNestedString(sample, "Authentihash", "SHA256");
                        if (auth == null) auth = GetString(sample, "Authentihash"); // запас на простой формат
                        if (IsHex(auth, 64) && string.IsNullOrEmpty(entry.Authentihash))
                            entry.Authentihash = auth.ToUpperInvariant();
                    }
                }
            }

            // Общий проход — ловим SHA-256 в других местах (как раньше), не затирая уже найденное.
            foreach (KeyValuePair<string, object> pair in dict)
            {
                if (string.Equals(pair.Key, "SHA256", StringComparison.OrdinalIgnoreCase))
                {
                    string sha = pair.Value as string;
                    if (IsHex(sha, 64))
                    {
                        string key = sha.ToUpperInvariant();
                        if (!bySha256.ContainsKey(key))
                            bySha256[key] = new HashEntry { Sha256 = key };
                    }
                }
                Collect(pair.Value, bySha256);
            }
        }

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

        // Достаём строку из вложенного словаря: dict[outerKey][innerKey].
        private static string GetNestedString(Dictionary<string, object> dict, string outerKey, string innerKey)
        {
            object value;
            if (!dict.TryGetValue(outerKey, out value)) return null;
            var inner = value as Dictionary<string, object>;
            if (inner == null) return null;
            return GetString(inner, innerKey);
        }

        private static bool IsHex(string value, int expectedLength)
        {
            if (value == null || value.Length != expectedLength) return false;
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
