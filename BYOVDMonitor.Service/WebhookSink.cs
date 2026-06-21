using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;

namespace BYOVDMonitor.Service
{
    // Отправка оповещений по HTTP POST JSON. Адрес задаётся в config.json (WebhookUrl).
    // Формат полезной нагрузки удобен для SIEM/Slack/универсального приёмника.
    internal class WebhookSink
    {
        private static readonly HttpClient Http = CreateHttpClient();
        private readonly string _url;

        public WebhookSink(string url) { _url = url; }

        public bool IsEnabled { get { return !string.IsNullOrEmpty(_url); } }

        public void Send(Detection detection)
        {
            if (!IsEnabled) return;

            try
            {
                var payload = new Dictionary<string, object>
                {
                    { "event", "byovd_detection" },
                    { "time", detection.Time.ToUniversalTime().ToString("o") },
                    { "host", Environment.MachineName },
                    { "file", detection.FilePath },
                    { "sha256", detection.Sha256 },
                    { "match", detection.DriverName },
                    { "source", detection.Source }
                };
                string json = Json.Serialize(payload);

                var content = new StringContent(json, Encoding.UTF8, "application/json");
                // Не блокируем поток обнаружения; ошибка отправки логируется службой.
                Http.PostAsync(_url, content).ContinueWith(t =>
                {
                    if (t.Exception != null)
                    {
                        Exception _ = t.Exception; // помечаем наблюдённой
                    }
                });
            }
            catch
            {
                // Сетевые ошибки не должны валить службу.
            }
        }

        private static HttpClient CreateHttpClient()
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            var client = new HttpClient();
            client.Timeout = TimeSpan.FromSeconds(15);
            client.DefaultRequestHeaders.UserAgent.ParseAdd("BYOVDMonitorService/1.2");
            return client;
        }
    }
}
