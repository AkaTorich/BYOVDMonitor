using System;
using System.Diagnostics;

namespace BYOVDMonitor.Service
{
    // Запись в системный журнал событий Windows (Application).
    // Источник регистрируется при установке службы.
    internal class EventLogSink
    {
        // Идентификаторы событий — постоянные, чтобы фильтры SIEM ловили по EventID.
        public const int EventIdServiceInfo = 1000;
        public const int EventIdAlert = 2000;
        public const int EventIdWarning = 3000;
        public const int EventIdError = 4000;

        private readonly EventLog _log;

        public EventLogSink(string source)
        {
            _log = new EventLog { Source = source, Log = "Application" };
        }

        public void Info(string message)
        {
            Write(EventLogEntryType.Information, EventIdServiceInfo, message);
        }

        public void Warning(string message)
        {
            Write(EventLogEntryType.Warning, EventIdWarning, message);
        }

        public void Error(string message)
        {
            Write(EventLogEntryType.Error, EventIdError, message);
        }

        // Тревога об обнаружении уязвимого драйвера.
        public void Alert(Detection detection)
        {
            string text =
                "VULNERABLE DRIVER DETECTED\r\n" +
                "Host: " + Environment.MachineName + "\r\n" +
                "File: " + detection.FilePath + "\r\n" +
                "SHA-256: " + detection.Sha256 + "\r\n" +
                "Match: " + detection.DriverName + "\r\n" +
                "Source: " + detection.Source;
            Write(EventLogEntryType.Error, EventIdAlert, text);
        }

        private void Write(EventLogEntryType type, int eventId, string message)
        {
            try
            {
                // Журнал событий ограничивает запись 31 839 символами; режем длинное.
                if (message != null && message.Length > 30000)
                    message = message.Substring(0, 30000) + "... [обрезано]";
                _log.WriteEntry(message ?? string.Empty, type, eventId);
            }
            catch
            {
                // Журнал событий недоступен — продолжаем без него.
            }
        }
    }
}
