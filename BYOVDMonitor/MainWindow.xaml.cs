using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;

namespace BYOVDMonitor
{
    public partial class MainWindow : Window
    {
        private readonly AppConfig _config;
        private readonly HashListService _hashes;
        private readonly MonitorService _monitor;

        private readonly ObservableCollection<Detection> _detections = new ObservableCollection<Detection>();
        private readonly ObservableCollection<MonitoredFolder> _folders = new ObservableCollection<MonitoredFolder>();

        private readonly DispatcherTimer _updateTimer = new DispatcherTimer();
        private readonly DispatcherTimer _rescanTimer = new DispatcherTimer();
        private Storyboard _blink;

        private bool _alertActive;
        private bool _checkingUpdates;

        // Цвета состояний лампы.
        private static readonly Color ColorIdle = Color.FromRgb(0x5A, 0x64, 0x72);  // серый — нет базы/ожидание
        private static readonly Color ColorClear = Color.FromRgb(0x35, 0xC5, 0x6A); // зелёный — чисто
        private static readonly Color ColorAlert = Color.FromRgb(0xFF, 0x4D, 0x4D); // красный — тревога

        public MainWindow()
        {
            InitializeComponent();

            _config = AppConfig.Load();
            _hashes = new HashListService();
            // Сервис мониторинга создаётся в UI-потоке, чтобы захватить его контекст для событий.
            _monitor = new MonitorService(_hashes, _config);
            _monitor.Detected += OnDetected;
            _monitor.Error += OnMonitorError;

            DetectionsList.ItemsSource = _detections;
            FoldersList.ItemsSource = _folders;
            foreach (MonitoredFolder folder in _config.Folders)
                _folders.Add(folder);

            SoundCheck.IsChecked = _config.SoundEnabled;
            MhrCheck.IsChecked = _config.MhrEnabled;

            _blink = (Storyboard)FindResource("BlinkStoryboard");

            _updateTimer.Interval = TimeSpan.FromHours(1);
            _updateTimer.Tick += (s, e) => { _ = CheckUpdatesAsync(true); };

            _rescanTimer.Interval = TimeSpan.FromMinutes(_config.RescanIntervalMinutes);
            _rescanTimer.Tick += (s, e) => _monitor.Rescan();

            Loaded += OnLoaded;
            Closed += OnClosed;

            RefreshLampIdle();
        }

        private async void OnLoaded(object sender, RoutedEventArgs e)
        {
            _hashes.Load();
            UpdateListStatus();

            // База ещё не загружена — предлагаем скачать сразу при старте.
            if (!_hashes.HasLocalList)
            {
                MessageBoxResult answer = MessageBox.Show(this,
                    "The vulnerable driver hash list is not loaded.\n\nDownload it now from loldrivers.io?",
                    "BYOVD Monitor", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (answer == MessageBoxResult.Yes)
                    await DownloadListAsync();
            }
            else if (_hashes.NeedsFreshDownload)
            {
                // Старый формат базы (без Imphash/Authentihash) — обновляем без диалога.
                StatusBarText.Text = "Upgrading hash list to extended schema (Imphash/Authentihash)...";
                _ = DownloadListAsync();
            }
            else
            {
                // База есть — тихо проверим обновление в фоне (намеренно без await).
                _ = CheckUpdatesAsync(true);
            }

            StartMonitoring();

            _updateTimer.Start();
            _rescanTimer.Start();
        }

        private void OnClosed(object sender, EventArgs e)
        {
            try { _monitor.Stop(); } catch { }
            SaveConfig();
        }

        // ===== База хешей =====

        private async void OnDownloadClick(object sender, RoutedEventArgs e)
        {
            await DownloadListAsync();
        }

        private async System.Threading.Tasks.Task DownloadListAsync()
        {
            DownloadButton.IsEnabled = false;
            CheckUpdateButton.IsEnabled = false;
            StatusBarText.Text = "Downloading hash list...";
            try
            {
                int count = await _hashes.DownloadAndApplyAsync(_config.HashListUrl);
                UpdateListStatus();
                StatusBarText.Text = "Hash list downloaded: " + count + " entries";
                if (_monitor.IsRunning) _monitor.Rescan();
            }
            catch (Exception ex)
            {
                StatusBarText.Text = "Hash list download failed";
                MessageBox.Show(this, "Failed to download the hash list:\n\n" + ex.Message,
                    "BYOVD Monitor", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            finally
            {
                DownloadButton.IsEnabled = true;
                CheckUpdateButton.IsEnabled = true;
                if (!_alertActive) RefreshLampIdle();
            }
        }

        private async void OnCheckUpdateClick(object sender, RoutedEventArgs e)
        {
            await CheckUpdatesAsync(false);
        }

        // silent — не показывать сообщение "обновлений нет" (для фоновой/ежечасной проверки).
        private async System.Threading.Tasks.Task CheckUpdatesAsync(bool silent)
        {
            if (_checkingUpdates) return;
            if (!_hashes.HasLocalList)
            {
                if (!silent) await DownloadListAsync();
                return;
            }

            _checkingUpdates = true;
            CheckUpdateButton.IsEnabled = false;
            if (!silent) StatusBarText.Text = "Checking for hash list updates...";
            try
            {
                UpdateCheckResult result = await _hashes.CheckForUpdateAsync(_config.HashListUrl);

                if (result.Error != null)
                {
                    if (!silent)
                        MessageBox.Show(this, "Failed to check for updates:\n\n" + result.Error,
                            "BYOVD Monitor", MessageBoxButton.OK, MessageBoxImage.Warning);
                    StatusBarText.Text = "Update check failed";
                    return;
                }

                if (result.UpdateAvailable)
                {
                    MessageBoxResult answer = MessageBox.Show(this,
                        "A hash list update is available (" + result.NewCount + " entries).\n\nDownload now?",
                        "BYOVD Monitor", MessageBoxButton.YesNo, MessageBoxImage.Information);
                    if (answer == MessageBoxResult.Yes)
                    {
                        _hashes.ApplyUpdate(result);
                        UpdateListStatus();
                        if (_monitor.IsRunning) _monitor.Rescan();
                        StatusBarText.Text = "Hash list updated: " + result.NewCount + " entries";
                    }
                    else
                    {
                        StatusBarText.Text = "Update available — click \"Download list\" to fetch";
                    }
                }
                else
                {
                    if (!silent) StatusBarText.Text = "No updates available";
                }
            }
            finally
            {
                _checkingUpdates = false;
                CheckUpdateButton.IsEnabled = true;
            }
        }

        private void UpdateListStatus()
        {
            if (_hashes.HasLocalList)
            {
                string when = _hashes.LastUpdatedUtc.HasValue
                    ? _hashes.LastUpdatedUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm")
                    : "—";
                ListStatusText.Text = "Hash list: SHA-256 " + _hashes.Count
                    + ", Imphash " + _hashes.ImphashCount
                    + ", Authentihash " + _hashes.AuthentihashCount
                    + ". Updated " + when;
                DownloadButton.Content = "Refresh list";
            }
            else
            {
                ListStatusText.Text = "Hash list not loaded";
                DownloadButton.Content = "Download list";
            }
            if (!_alertActive) RefreshLampIdle();
        }

        // ===== Мониторинг =====

        private void StartMonitoring()
        {
            _monitor.Start(_folders);
            if (!_alertActive) RefreshLampIdle();
        }

        private void OnDetected(Detection detection)
        {
            _detections.Insert(0, detection);

            _alertActive = true;
            ClearAlertButton.IsEnabled = true;

            SetLamp(ColorAlert, true,
                "VULNERABLE DRIVER DETECTED",
                detection.DriverName + "\n" + detection.FilePath);

            StatusBarText.Text = "Detection: " + detection.FileName + "  (" + detection.DriverName + ")";

            if (SoundCheck.IsChecked == true)
            {
                try { System.Media.SystemSounds.Hand.Play(); } catch { }
            }

            // Привлекаем внимание: показываем и подсвечиваем окно.
            try
            {
                if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
                Activate();
            }
            catch { }
        }

        private void OnMonitorError(string message)
        {
            StatusBarText.Text = message;
        }

        // ===== Лампа =====

        private void RefreshLampIdle()
        {
            if (_alertActive) return;

            if (!_hashes.HasLocalList)
            {
                SetLamp(ColorIdle, false, "No hash list", "Download the hash list");
            }
            else if (_monitor != null && _monitor.IsRunning && _folders.Count > 0)
            {
                SetLamp(ColorClear, false, "Clean", "Folders watched: " + _folders.Count);
            }
            else
            {
                SetLamp(ColorIdle, false, "Idle", "Add folders to monitor");
            }
        }

        private void SetLamp(Color color, bool blink, string status, string sub)
        {
            // Стекло лампы — радиальный градиент от осветлённого центра к основному цвету.
            Color bright = Color.FromRgb(
                (byte)Math.Min(255, color.R + 70),
                (byte)Math.Min(255, color.G + 70),
                (byte)Math.Min(255, color.B + 70));

            var glass = new RadialGradientBrush();
            glass.GradientOrigin = new Point(0.4, 0.35);
            glass.Center = new Point(0.5, 0.5);
            glass.RadiusX = 0.65;
            glass.RadiusY = 0.65;
            glass.GradientStops.Add(new GradientStop(bright, 0));
            glass.GradientStops.Add(new GradientStop(color, 1));

            LampGlass.Fill = glass;
            LampGlow.Fill = new SolidColorBrush(color);

            StatusText.Text = status;
            StatusSubText.Text = sub;

            if (blink)
            {
                _blink.Begin(this, true);
            }
            else
            {
                _blink.Stop(this);
                LampGlow.Opacity = 0.5;
            }
        }

        private void OnClearAlertClick(object sender, RoutedEventArgs e)
        {
            _alertActive = false;
            ClearAlertButton.IsEnabled = false;
            RefreshLampIdle();
            StatusBarText.Text = "Alert cleared";
        }

        // ===== Папки =====

        private void OnBrowseClick(object sender, RoutedEventArgs e)
        {
            using (var dialog = new System.Windows.Forms.FolderBrowserDialog())
            {
                dialog.Description = "Select a folder to monitor";
                if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                    FolderPathBox.Text = dialog.SelectedPath;
            }
        }

        private void OnAddFolderClick(object sender, RoutedEventArgs e)
        {
            string path = (FolderPathBox.Text ?? string.Empty).Trim();
            if (path.Length == 0) return;

            if (!Directory.Exists(path))
            {
                MessageBox.Show(this, "Folder does not exist:\n" + path,
                    "BYOVD Monitor", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            foreach (MonitoredFolder existing in _folders)
            {
                if (string.Equals(existing.Path, path, StringComparison.OrdinalIgnoreCase))
                {
                    StatusBarText.Text = "Folder already in list";
                    return;
                }
            }

            _folders.Add(new MonitoredFolder
            {
                Path = path,
                IncludeSubdirectories = SubfoldersCheck.IsChecked == true
            });

            FolderPathBox.Text = string.Empty;
            SaveConfig();
            StartMonitoring();
            StatusBarText.Text = "Folder added: " + path;
        }

        private void OnRemoveFolderClick(object sender, RoutedEventArgs e)
        {
            var button = sender as System.Windows.Controls.Button;
            if (button == null) return;
            var folder = button.Tag as MonitoredFolder;
            if (folder == null) return;

            _folders.Remove(folder);
            SaveConfig();
            StartMonitoring();
            StatusBarText.Text = "Folder removed";
        }

        private void OnScanNowClick(object sender, RoutedEventArgs e)
        {
            _monitor.Rescan();
            StatusBarText.Text = "Rescanning folders...";
        }

        // ===== Журнал =====

        private void OnDetectionDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            OpenSelectedFolder();
        }

        private void OnOpenFolderClick(object sender, RoutedEventArgs e)
        {
            OpenSelectedFolder();
        }

        private void OpenSelectedFolder()
        {
            var detection = DetectionsList.SelectedItem as Detection;
            if (detection == null)
            {
                StatusBarText.Text = "Select an entry in the log first";
                return;
            }

            try
            {
                if (File.Exists(detection.FilePath))
                {
                    // Открыть Проводник с выделенным файлом.
                    Process.Start(new ProcessStartInfo("explorer.exe",
                        "/select,\"" + detection.FilePath + "\"") { UseShellExecute = true });
                }
                else
                {
                    string dir = Path.GetDirectoryName(detection.FilePath);
                    if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                        Process.Start(new ProcessStartInfo("explorer.exe", "\"" + dir + "\"") { UseShellExecute = true });
                    else
                        StatusBarText.Text = "File and folder not found";
                }
            }
            catch (Exception ex)
            {
                StatusBarText.Text = "Failed to open folder: " + ex.Message;
            }
        }

        private void OnCopyHashClick(object sender, RoutedEventArgs e)
        {
            var detection = DetectionsList.SelectedItem as Detection;
            if (detection == null) return;
            try
            {
                Clipboard.SetText(detection.Sha256);
                StatusBarText.Text = "SHA-256 copied to clipboard";
            }
            catch { }
        }

        private void OnClearLogClick(object sender, RoutedEventArgs e)
        {
            _detections.Clear();
            StatusBarText.Text = "Log cleared";
        }

        // Ручная проверка выбранного файла по loldrivers и MHR.
        private async void OnCheckFileClick(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog();
            dialog.Title = "Select a file to check";
            dialog.Filter = "All files (*.*)|*.*";
            if (dialog.ShowDialog(this) != true) return;

            string path = dialog.FileName;
            StatusBarText.Text = "Checking file: " + System.IO.Path.GetFileName(path) + "...";
            try
            {
                Detection detection = await System.Threading.Tasks.Task.Run(() => _monitor.CheckFile(path, true));
                if (detection != null)
                {
                    OnDetected(detection); // занесёт в журнал и поднимет тревогу
                }
                else
                {
                    StatusBarText.Text = "File clean: not found in loldrivers or MHR";
                    MessageBox.Show(this, "File not found in any source:\n" + path,
                        "BYOVD Monitor", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                StatusBarText.Text = "File check error: " + ex.Message;
            }
        }

        // ===== Настройки =====

        private void OnSoundToggle(object sender, RoutedEventArgs e)
        {
            // Событие может прилететь во время InitializeComponent() — поля окна ещё null.
            if (_config == null) return;
            _config.SoundEnabled = SoundCheck.IsChecked == true;
            _config.Save();
        }

        private void OnMhrToggle(object sender, RoutedEventArgs e)
        {
            // Событие может прилететь во время InitializeComponent() — поля окна ещё null.
            // Монитор читает _config.MhrEnabled на лету — перезапуск не нужен.
            if (_config == null) return;
            _config.MhrEnabled = MhrCheck.IsChecked == true;
            _config.Save();
        }

        private void SaveConfig()
        {
            _config.Folders = new List<MonitoredFolder>(_folders);
            _config.SoundEnabled = SoundCheck.IsChecked == true;
            _config.MhrEnabled = MhrCheck.IsChecked == true;
            _config.Save();
        }
    }
}
