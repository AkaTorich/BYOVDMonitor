using System;
using System.IO;
using System.ServiceProcess;
using System.Threading;

namespace BYOVDMonitor.Service
{
    // Тело службы Windows: запуск/остановка движка обнаружения, журналирование,
    // периодическая проверка обновлений базы хешей.
    internal class WorkerService : ServiceBase
    {
        private readonly EventLogSink _eventSink;
        private AppConfig _config;
        private HashListService _hashes;
        private MonitorService _monitor;
        private WebhookSink _webhook;
        private Timer _updateTimer;
        private int _updateBusy; // защита от наложения проверок обновлений

        public WorkerService()
        {
            ServiceName = Program.ServiceName;
            CanStop = true;
            CanShutdown = true;
            AutoLog = false; // используем свой источник, не "BYOVDMonitor service"
            _eventSink = new EventLogSink(Program.EventLogSource);
        }

        protected override void OnStart(string[] args)
        {
            try
            {
                Directory.CreateDirectory(AppConfig.DataDirectory);
                _config = AppConfig.Load();
                _webhook = new WebhookSink(_config.WebhookUrl);

                _hashes = new HashListService();
                _hashes.Load();

                _monitor = new MonitorService(_hashes, _config);
                _monitor.Detected += OnDetected;
                _monitor.Error += OnMonitorError;
                _monitor.Start(_config.Folders);

                int folderCount = _config.Folders == null ? 0 : _config.Folders.Count;
                _eventSink.Info(
                    "BYOVD Monitor service started.\r\n" +
                    "Data dir: " + AppConfig.DataDirectory + "\r\n" +
                    "Hashes loaded: " + _hashes.Count + "\r\n" +
                    "Monitored folders: " + folderCount + "\r\n" +
                    "MHR: " + (_config.MhrEnabled ? "enabled" : "disabled") + "\r\n" +
                    "Webhook: " + (_webhook.IsEnabled ? "enabled" : "disabled"));

                if (folderCount == 0)
                    _eventSink.Warning("No folders configured. Edit " +
                        Path.Combine(AppConfig.DataDirectory, "config.json") + " and restart the service.");

                if (!_hashes.HasLocalList)
                    _eventSink.Warning("Hash list is empty. The service will try to download it shortly.");

                // Первая проверка обновлений через минуту после старта, далее раз в час.
                _updateTimer = new Timer(UpdateTimerTick, null,
                    TimeSpan.FromMinutes(1), TimeSpan.FromHours(1));
            }
            catch (Exception ex)
            {
                try { _eventSink.Error("OnStart failed: " + ex); } catch { }
                throw;
            }
        }

        protected override void OnStop()
        {
            try { if (_updateTimer != null) _updateTimer.Dispose(); } catch { }
            try { if (_monitor != null) _monitor.Stop(); } catch { }
            try { _eventSink.Info("BYOVD Monitor service stopped."); } catch { }
        }

        protected override void OnShutdown()
        {
            OnStop();
        }

        // Обработчик сработки — попадает в журнал Windows и (если включён) в webhook.
        private void OnDetected(Detection detection)
        {
            try { _eventSink.Alert(detection); } catch { }
            try { if (_webhook != null) _webhook.Send(detection); } catch { }
        }

        private void OnMonitorError(string message)
        {
            try { _eventSink.Warning(message); } catch { }
        }

        // Тик таймера обновления базы: запускает асинхронную задачу без блокировки потока.
        private void UpdateTimerTick(object state)
        {
            if (Interlocked.Exchange(ref _updateBusy, 1) == 1) return;
            _ = CheckUpdateAsync();
        }

        private async System.Threading.Tasks.Task CheckUpdateAsync()
        {
            try
            {
                if (!_hashes.HasLocalList)
                {
                    int n = await _hashes.DownloadAndApplyAsync(_config.HashListUrl).ConfigureAwait(false);
                    _eventSink.Info("Hash list downloaded: " + n + " entries.");
                    _monitor.Rescan();
                    return;
                }

                UpdateCheckResult result = await _hashes.CheckForUpdateAsync(_config.HashListUrl).ConfigureAwait(false);
                if (result.Error != null)
                {
                    _eventSink.Warning("Hash list update check failed: " + result.Error);
                    return;
                }
                if (result.UpdateAvailable)
                {
                    _hashes.ApplyUpdate(result);
                    _eventSink.Info("Hash list updated: " + result.NewCount + " entries.");
                    _monitor.Rescan();
                }
            }
            catch (Exception ex)
            {
                _eventSink.Warning("Hash list update task failed: " + ex.Message);
            }
            finally
            {
                Interlocked.Exchange(ref _updateBusy, 0);
            }
        }

        // Запуск тех же шагов из консоли (без ServiceBase) — для отладки.
        public void RunConsole()
        {
            OnStart(new string[0]);
            Console.WriteLine("Service core started in console mode. Press Ctrl+C to stop.");
            var quit = new ManualResetEventSlim(false);
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; quit.Set(); };
            quit.Wait();
            OnStop();
        }
    }
}
