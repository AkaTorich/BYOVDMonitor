using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace BYOVDMonitor
{
    // Анализ PE-образа без сторонних библиотек: расчёт Imphash и Authentihash.
    //
    // Imphash (Mandiant) — MD5 от строки "dll1.func1,dll1.func2,dll2.func3,..." (всё в нижнем регистре,
    //   расширения .dll/.ocx/.sys в именах библиотек обрезаются). Стабилен к косметической правке байт
    //   (изменению строк, ресурсов, отладочной информации) — меняется только при перекомпиляции с другими
    //   зависимостями.
    //
    // Authentihash — SHA-256 от тела PE-файла с пропуском поля CheckSum (4 байта), записи Security
    //   в DataDirectory (8 байт) и самого подписного блока в конце файла. Поломается при правке любых
    //   байт исполняемого образа, но не при перевыпуске/удалении подписи как таковой.
    internal static class PeAnalyzer
    {
        // Возвращает Imphash (верхний регистр hex) или null при ошибке разбора / отсутствии импортов.
        public static string ComputeImphash(byte[] data)
        {
            try
            {
                PeLayout pe;
                if (!ParseLayout(data, out pe)) return null;

                // DataDirectory[1] — Import Directory.
                if (pe.NumberOfDataDirectories < 2) return null;
                int importDirOffset = pe.DataDirectoryOffset + 1 * 8;
                if (importDirOffset + 8 > data.Length) return null;
                int importRva = ReadInt32(data, importDirOffset);
                int importSize = ReadInt32(data, importDirOffset + 4);
                if (importRva == 0 || importSize == 0) return null;

                int importTableOffset;
                if (!Rva2File(pe, importRva, out importTableOffset)) return null;

                var entries = new List<string>();
                int pos = importTableOffset;

                while (pos + 20 <= data.Length)
                {
                    int origThunkRva = ReadInt32(data, pos + 0);   // OriginalFirstThunk
                    int nameRva = ReadInt32(data, pos + 12);
                    int firstThunkRva = ReadInt32(data, pos + 16); // FirstThunk

                    // Конец массива — все поля нулевые.
                    if (origThunkRva == 0 && nameRva == 0 && firstThunkRva == 0) break;
                    pos += 20;

                    int nameOffset;
                    if (!Rva2File(pe, nameRva, out nameOffset)) continue;
                    string dllName = ReadAsciiZ(data, nameOffset, 128);
                    if (string.IsNullOrEmpty(dllName)) continue;
                    string normalizedDll = NormalizeDllName(dllName);

                    int thunkRva = origThunkRva != 0 ? origThunkRva : firstThunkRva;
                    int thunkOffset;
                    if (!Rva2File(pe, thunkRva, out thunkOffset)) continue;

                    int thunkSize = pe.IsPE32Plus ? 8 : 4;
                    int thunkPos = thunkOffset;

                    // Защита от зацикливания на повреждённых файлах.
                    int safetyLimit = 4096;
                    while (thunkPos + thunkSize <= data.Length && safetyLimit-- > 0)
                    {
                        long thunkValue;
                        bool isOrdinal;
                        if (pe.IsPE32Plus)
                        {
                            thunkValue = ReadInt64(data, thunkPos);
                            isOrdinal = (thunkValue & unchecked((long)0x8000000000000000L)) != 0;
                        }
                        else
                        {
                            thunkValue = (uint)ReadInt32(data, thunkPos);
                            isOrdinal = (thunkValue & 0x80000000L) != 0;
                        }

                        if (thunkValue == 0) break;

                        string funcEntry;
                        if (isOrdinal)
                        {
                            // Импорт по ординалу — pefile использует "ord<N>" (без сопоставления имён).
                            long ord = thunkValue & 0xFFFF;
                            funcEntry = normalizedDll + ".ord" + ord;
                        }
                        else
                        {
                            int hintNameRva = (int)(thunkValue & 0x7FFFFFFFL);
                            int hintNameOffset;
                            if (!Rva2File(pe, hintNameRva, out hintNameOffset))
                            {
                                thunkPos += thunkSize;
                                continue;
                            }
                            // IMAGE_IMPORT_BY_NAME: WORD hint, затем ASCIIZ имя.
                            int nameStart = hintNameOffset + 2;
                            string funcName = ReadAsciiZ(data, nameStart, 512);
                            if (string.IsNullOrEmpty(funcName))
                            {
                                thunkPos += thunkSize;
                                continue;
                            }
                            funcEntry = normalizedDll + "." + funcName.ToLowerInvariant();
                        }

                        entries.Add(funcEntry);
                        thunkPos += thunkSize;
                    }
                }

                if (entries.Count == 0) return null;

                string joined = string.Join(",", entries);
                using (MD5 md5 = MD5.Create())
                    return ToHex(md5.ComputeHash(Encoding.ASCII.GetBytes(joined)));
            }
            catch
            {
                return null;
            }
        }

        // Возвращает Authentihash (верхний регистр hex) или null при ошибке.
        public static string ComputeAuthentihash(byte[] data)
        {
            try
            {
                PeLayout pe;
                if (!ParseLayout(data, out pe)) return null;

                int checksumOffset = pe.OptionalHeaderOffset + 64;          // 4 байта
                int securityDirOffset = pe.DataDirectoryOffset + 4 * 8;     // 8 байт (DataDirectory[4])

                if (checksumOffset + 4 > data.Length) return null;
                if (securityDirOffset + 8 > data.Length) return null;

                int certFileOffset = ReadInt32(data, securityDirOffset);    // в Security это файловый offset, не RVA
                int certSize = ReadInt32(data, securityDirOffset + 4);

                using (SHA256 sha = SHA256.Create())
                {
                    // 1. Хешируем [0, checksumOffset).
                    sha.TransformBlock(data, 0, checksumOffset, null, 0);

                    // 2. Пропускаем 4 байта CheckSum.
                    int pos = checksumOffset + 4;

                    // 3. Хешируем [pos, securityDirOffset).
                    if (securityDirOffset > pos)
                        sha.TransformBlock(data, pos, securityDirOffset - pos, null, 0);

                    // 4. Пропускаем 8 байт записи Security в DataDirectory.
                    pos = securityDirOffset + 8;

                    if (certFileOffset > 0 && certSize > 0 && certFileOffset + certSize <= data.Length)
                    {
                        // 5a. Хешируем до начала подписного блока.
                        if (certFileOffset > pos)
                            sha.TransformBlock(data, pos, certFileOffset - pos, null, 0);
                        // 6. Пропускаем сам подписной блок.
                        pos = certFileOffset + certSize;
                    }

                    // 5b/7. Хешируем хвост файла (после подписи или до конца, если её нет).
                    if (pos < data.Length)
                        sha.TransformBlock(data, pos, data.Length - pos, null, 0);

                    sha.TransformFinalBlock(EmptyBuffer, 0, 0);
                    return ToHex(sha.Hash);
                }
            }
            catch
            {
                return null;
            }
        }

        private static readonly byte[] EmptyBuffer = new byte[0];

        // Полезные смещения в PE-файле и список секций.
        private struct PeLayout
        {
            public int OptionalHeaderOffset;
            public int DataDirectoryOffset;
            public int NumberOfDataDirectories;
            public bool IsPE32Plus;
            public List<Section> Sections;
        }

        private struct Section
        {
            public int VirtualAddress;
            public int VirtualSize;
            public int PointerToRawData;
            public int SizeOfRawData;
        }

        private static bool ParseLayout(byte[] data, out PeLayout pe)
        {
            pe = default(PeLayout);

            if (data == null || data.Length < 64) return false;
            if (data[0] != 0x4D || data[1] != 0x5A) return false; // "MZ"

            int peSigOffset = ReadInt32(data, 0x3C);
            if (peSigOffset <= 0 || peSigOffset + 24 > data.Length) return false;

            // Проверка сигнатуры "PE\0\0"
            if (data[peSigOffset] != 0x50 || data[peSigOffset + 1] != 0x45 ||
                data[peSigOffset + 2] != 0 || data[peSigOffset + 3] != 0)
                return false;

            int fileHeaderOffset = peSigOffset + 4;
            ushort numberOfSections = ReadUInt16(data, fileHeaderOffset + 2);
            ushort sizeOfOptionalHeader = ReadUInt16(data, fileHeaderOffset + 16);

            int optHeaderOffset = fileHeaderOffset + 20;
            if (optHeaderOffset + 2 > data.Length) return false;
            ushort magic = ReadUInt16(data, optHeaderOffset);
            bool isPE32Plus;
            if (magic == 0x10B) isPE32Plus = false;
            else if (magic == 0x20B) isPE32Plus = true;
            else return false;

            int numberOfRvaAndSizesOffset = optHeaderOffset + (isPE32Plus ? 108 : 92);
            if (numberOfRvaAndSizesOffset + 4 > data.Length) return false;
            int numberOfDataDirectories = ReadInt32(data, numberOfRvaAndSizesOffset);
            if (numberOfDataDirectories < 0 || numberOfDataDirectories > 16) return false;

            int dataDirectoryOffset = optHeaderOffset + (isPE32Plus ? 112 : 96);
            if (dataDirectoryOffset + numberOfDataDirectories * 8 > data.Length) return false;

            int sectionsOffset = optHeaderOffset + sizeOfOptionalHeader;
            var sections = new List<Section>(numberOfSections);
            for (int i = 0; i < numberOfSections; i++)
            {
                int s = sectionsOffset + i * 40;
                if (s + 40 > data.Length) return false;
                Section sec;
                sec.VirtualSize = ReadInt32(data, s + 8);
                sec.VirtualAddress = ReadInt32(data, s + 12);
                sec.SizeOfRawData = ReadInt32(data, s + 16);
                sec.PointerToRawData = ReadInt32(data, s + 20);
                sections.Add(sec);
            }

            pe.OptionalHeaderOffset = optHeaderOffset;
            pe.DataDirectoryOffset = dataDirectoryOffset;
            pe.NumberOfDataDirectories = numberOfDataDirectories;
            pe.IsPE32Plus = isPE32Plus;
            pe.Sections = sections;
            return true;
        }

        // Перевод RVA в файловое смещение через карту секций.
        private static bool Rva2File(PeLayout pe, int rva, out int fileOffset)
        {
            fileOffset = 0;
            if (rva <= 0) return false;
            foreach (Section s in pe.Sections)
            {
                int span = Math.Max(s.VirtualSize, s.SizeOfRawData);
                if (rva >= s.VirtualAddress && rva < s.VirtualAddress + span)
                {
                    int offset = s.PointerToRawData + (rva - s.VirtualAddress);
                    if (offset < 0) return false;
                    fileOffset = offset;
                    return true;
                }
            }
            return false;
        }

        // Имя библиотеки в нижнем регистре, с обрезанным расширением .dll/.ocx/.sys (pefile-стиль).
        private static string NormalizeDllName(string name)
        {
            string lower = name.ToLowerInvariant();
            if (lower.Length > 4)
            {
                string tail = lower.Substring(lower.Length - 4);
                if (tail == ".dll" || tail == ".ocx" || tail == ".sys")
                    lower = lower.Substring(0, lower.Length - 4);
            }
            return lower;
        }

        private static string ReadAsciiZ(byte[] data, int offset, int maxLen)
        {
            if (offset < 0 || offset >= data.Length) return null;
            int end = Math.Min(offset + maxLen, data.Length);
            int i = offset;
            while (i < end && data[i] != 0) i++;
            if (i == offset) return string.Empty;
            return Encoding.ASCII.GetString(data, offset, i - offset);
        }

        private static int ReadInt32(byte[] data, int offset)
        {
            return data[offset]
                 | (data[offset + 1] << 8)
                 | (data[offset + 2] << 16)
                 | (data[offset + 3] << 24);
        }

        private static long ReadInt64(byte[] data, int offset)
        {
            uint lo = (uint)ReadInt32(data, offset);
            uint hi = (uint)ReadInt32(data, offset + 4);
            return (long)((ulong)hi << 32 | lo);
        }

        private static ushort ReadUInt16(byte[] data, int offset)
        {
            return (ushort)(data[offset] | (data[offset + 1] << 8));
        }

        private static string ToHex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            for (int i = 0; i < bytes.Length; i++)
                sb.Append(bytes[i].ToString("X2"));
            return sb.ToString();
        }
    }
}
