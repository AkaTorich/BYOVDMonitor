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
                    "База хешей уязвимых драйверов не загружена.\n\nЗагрузить её сейчас из loldrivers.io?",
                    "BYOVD Monitor", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (answer == MessageBoxResult.Yes)
                    await DownloadListAsync();
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
            StatusBarText.Text = "Загрузка базы хешей...";
            try
            {
                int count = await _hashes.DownloadAndApplyAsync(_config.HashListUrl);
                UpdateListStatus();
                StatusBarText.Text = "База загружена: " + count + " хешей";
                if (_monitor.IsRunning) _monitor.Rescan();
            }
            catch (Exception ex)
            {
                StatusBarText.Text = "Ошибка загрузки базы";
                MessageBox.Show(this, "Не удалось загрузить базу хешей:\n\n" + ex.Message,
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
            if (!silent) StatusBarText.Text = "Проверка обновлений базы...";
            try
            {
                UpdateCheckResult result = await _hashes.CheckForUpdateAsync(_config.HashListUrl);

                if (result.Error != null)
                {
                    if (!silent)
                        MessageBox.Show(this, "Не удалось проверить обновления:\n\n" + result.Error,
                            "BYOVD Monitor", MessageBoxButton.OK, MessageBoxImage.Warning);
                    StatusBarText.Text = "Проверка обновлений не удалась";
                    return;
                }

                if (result.UpdateAvailable)
                {
                    MessageBoxResult answer = MessageBox.Show(this,
                        "Доступно обновление базы хешей (" + result.NewCount + " записей).\n\nЗагрузить?",
                        "BYOVD Monitor", MessageBoxButton.YesNo, MessageBoxImage.Information);
                    if (answer == MessageBoxResult.Yes)
                    {
                        _hashes.ApplyUpdate(result);
                        UpdateListStatus();
                        if (_monitor.IsRunning) _monitor.Rescan();
                        StatusBarText.Text = "База обновлена: " + result.NewCount + " хешей";
                    }
                    else
                    {
                        StatusBarText.Text = "Доступно обновление базы — нажмите \"Обновить список\"";
                    }
                }
                else
                {
                    if (!silent) StatusBarText.Text = "Обновлений нет";
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
                ListStatusText.Text = "База: " + _hashes.Count + " хешей, обновлена " + when;
                DownloadButton.Content = "Обновить список";
            }
            else
            {
                ListStatusText.Text = "База хешей не загружена";
                DownloadButton.Content = "Загрузить список";
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
                "ОБНАРУЖЕН УЯЗВИМЫЙ ДРАЙВЕР",
                detection.DriverName + "\n" + detection.FilePath);

            StatusBarText.Text = "Обнаружение: " + detection.FileName + "  (" + detection.DriverName + ")";

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
                SetLamp(ColorIdle, false, "Нет базы", "Загрузите список хешей");
            }
            else if (_monitor != null && _monitor.IsRunning && _folders.Count > 0)
            {
                SetLamp(ColorClear, false, "Чисто", "Наблюдается папок: " + _folders.Count);
            }
            else
            {
                SetLamp(ColorIdle, false, "Ожидание", "Добавьте папки для наблюдения");
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
            StatusBarText.Text = "Тревога сброшена";
        }

        // ===== Папки =====

        private void OnBrowseClick(object sender, RoutedEventArgs e)
        {
            using (var dialog = new System.Windows.Forms.FolderBrowserDialog())
            {
                dialog.Description = "Выберите папку для наблюдения";
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
                MessageBox.Show(this, "Папка не существует:\n" + path,
                    "BYOVD Monitor", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            foreach (MonitoredFolder existing in _folders)
            {
                if (string.Equals(existing.Path, path, StringComparison.OrdinalIgnoreCase))
                {
                    StatusBarText.Text = "Папка уже в списке";
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
            StatusBarText.Text = "Папка добавлена: " + path;
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
            StatusBarText.Text = "Папка удалена";
        }

        private void OnScanNowClick(object sender, RoutedEventArgs e)
        {
            _monitor.Rescan();
            StatusBarText.Text = "Запущен повторный обход папок";
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
                StatusBarText.Text = "Выберите запись в журнале";
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
                        StatusBarText.Text = "Файл и папка не найдены";
                }
            }
            catch (Exception ex)
            {
                StatusBarText.Text = "Не удалось открыть папку: " + ex.Message;
            }
        }

        private void OnCopyHashClick(object sender, RoutedEventArgs e)
        {
            var detection = DetectionsList.SelectedItem as Detection;
            if (detection == null) return;
            try
            {
                Clipboard.SetText(detection.Sha256);
                StatusBarText.Text = "SHA-256 скопирован в буфер обмена";
            }
            catch { }
        }

        private void OnClearLogClick(object sender, RoutedEventArgs e)
        {
            _detections.Clear();
            StatusBarText.Text = "Журнал очищен";
        }

        // Ручная проверка выбранного файла по loldrivers и MHR.
        private async void OnCheckFileClick(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog();
            dialog.Title = "Выберите файл для проверки";
            dialog.Filter = "Все файлы (*.*)|*.*";
            if (dialog.ShowDialog(this) != true) return;

            string path = dialog.FileName;
            StatusBarText.Text = "Проверка файла: " + System.IO.Path.GetFileName(path) + "...";
            try
            {
                Detection detection = await System.Threading.Tasks.Task.Run(() => _monitor.CheckFile(path, true));
                if (detection != null)
                {
                    OnDetected(detection); // занесёт в журнал и поднимет тревогу
                }
                else
                {
                    StatusBarText.Text = "Файл чист: не найден ни в loldrivers, ни в MHR";
                    MessageBox.Show(this, "Файл не найден в базах:\n" + path,
                        "BYOVD Monitor", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                StatusBarText.Text = "Ошибка проверки файла: " + ex.Message;
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
