using System.IO;

namespace BYOVDMonitor
{
    // Быстрая проверка: является ли файл PE-образом (драйвер/EXE/DLL/OCX/SCR/EFI и т. д.).
    // Читается 64 байта DOS-заголовка и 4 байта PE-сигнатуры — это в сотни раз дешевле,
    // чем полный SHA-256, и отсекает текстовые/изображения/архивы до хеширования.
    internal static class PeProbe
    {
        public static bool IsPortableExecutable(string path)
        {
            try
            {
                using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                           FileShare.ReadWrite | FileShare.Delete, 256, FileOptions.SequentialScan))
                {
                    // DOS-заголовок — 64 байта, без него точно не PE.
                    if (stream.Length < 64) return false;

                    byte[] header = new byte[64];
                    if (stream.Read(header, 0, 64) < 64) return false;

                    // Сигнатура DOS "MZ" (0x5A4D в little-endian).
                    if (header[0] != 0x4D || header[1] != 0x5A) return false;

                    // e_lfanew — 4 байта по смещению 0x3C, указывают на PE-заголовок.
                    int peOffset = header[0x3C]
                                 | (header[0x3D] << 8)
                                 | (header[0x3E] << 16)
                                 | (header[0x3F] << 24);
                    if (peOffset <= 0 || peOffset > stream.Length - 4) return false;

                    stream.Seek(peOffset, SeekOrigin.Begin);
                    byte[] sig = new byte[4];
                    if (stream.Read(sig, 0, 4) < 4) return false;

                    // Сигнатура PE "PE\0\0".
                    return sig[0] == 0x50 && sig[1] == 0x45 && sig[2] == 0 && sig[3] == 0;
                }
            }
            catch
            {
                // Файл заблокирован, исчез или недоступен — пропускаем без хеширования,
                // следующий tick наблюдателя (Changed) попробует снова.
                return false;
            }
        }
    }
}
