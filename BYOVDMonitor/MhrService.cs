using System;
using System.Runtime.InteropServices;

namespace BYOVDMonitor
{
    // Результат проверки хеша в Team Cymru Malware Hash Registry.
    public class MhrResult
    {
        public bool Known { get; set; }          // хеш найден в базе MHR (вредоносный)
        public int DetectionRate { get; set; }   // процент детекта антивирусами
        public DateTime? LastSeen { get; set; }  // время последней встречи
        public string Error { get; set; }        // текст ошибки, если запрос не удался
    }

    // Проверка хеша файла в Team Cymru MHR через DNS TXT-запрос.
    // Без ключа и без сторонних библиотек: DNS-запрос делается напрямую через WinAPI DnsQuery_W.
    // Запрос вида <sha1>.malware.hash.cymru.com, ответ TXT: "<unix-время> <процент-детекта>".
    public class MhrService
    {
        private const string ZoneSuffix = ".malware.hash.cymru.com";
        private const ushort DNS_TYPE_TEXT = 0x0010;
        private const uint DNS_QUERY_STANDARD = 0;
        private const int DnsFreeRecordList = 1;

        // Коды результата DnsQuery, означающие "запись не найдена" (хеш чист/неизвестен).
        private const int DNS_ERROR_RCODE_NAME_ERROR = 9003; // NXDOMAIN
        private const int DNS_INFO_NO_RECORDS = 9501;

        [DllImport("dnsapi.dll", EntryPoint = "DnsQuery_W", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int DnsQuery_W(string name, ushort type, uint options, IntPtr extra,
            ref IntPtr queryResults, IntPtr reserved);

        [DllImport("dnsapi.dll")]
        private static extern void DnsRecordListFree(IntPtr records, int freeType);

        // Заголовок записи DNS_RECORD (до объединения Data). Раскладка корректна для x86 и x64.
        [StructLayout(LayoutKind.Sequential)]
        private struct DnsRecordHeader
        {
            public IntPtr pNext;
            public IntPtr pName;
            public ushort wType;
            public ushort wDataLength;
            public uint flags;
            public uint dwTtl;
            public uint dwReserved;
        }

        // Проверка хеша SHA-1 (40 hex). Возвращает результат; при недоступности DNS — Error.
        public MhrResult Lookup(string sha1Hex)
        {
            var result = new MhrResult();
            if (!IsHex40(sha1Hex))
            {
                result.Error = "Invalid SHA-1";
                return result;
            }

            string name = sha1Hex.ToLowerInvariant() + ZoneSuffix;
            IntPtr records = IntPtr.Zero;
            try
            {
                int rc = DnsQuery_W(name, DNS_TYPE_TEXT, DNS_QUERY_STANDARD, IntPtr.Zero, ref records, IntPtr.Zero);
                if (rc == DNS_ERROR_RCODE_NAME_ERROR || rc == DNS_INFO_NO_RECORDS)
                {
                    // Записи нет — хеш не числится в MHR.
                    result.Known = false;
                    return result;
                }
                if (rc != 0)
                {
                    result.Error = "DnsQuery rc=" + rc;
                    return result;
                }

                string txt = ReadFirstTxt(records);
                if (string.IsNullOrEmpty(txt))
                {
                    result.Known = false;
                    return result;
                }

                // Формат: "<unix-время> <процент-детекта>".
                result.Known = true;
                string[] parts = txt.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                long unixTime;
                if (parts.Length > 0 && long.TryParse(parts[0], out unixTime))
                    result.LastSeen = DateTimeOffset.FromUnixTimeSeconds(unixTime).UtcDateTime;
                int rate;
                if (parts.Length > 1 && int.TryParse(parts[1], out rate))
                    result.DetectionRate = rate;
                return result;
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                return result;
            }
            finally
            {
                if (records != IntPtr.Zero)
                    DnsRecordListFree(records, DnsFreeRecordList);
            }
        }

        // Чтение первой TXT-строки из связного списка записей DNS_RECORD.
        private static string ReadFirstTxt(IntPtr records)
        {
            int headerSize = Marshal.SizeOf(typeof(DnsRecordHeader));
            IntPtr current = records;
            while (current != IntPtr.Zero)
            {
                DnsRecordHeader header = (DnsRecordHeader)Marshal.PtrToStructure(current, typeof(DnsRecordHeader));
                if (header.wType == DNS_TYPE_TEXT)
                {
                    // Сразу за заголовком идёт DNS_TXT_DATA: dwStringCount, затем массив указателей на строки.
                    IntPtr dataPtr = IntPtr.Add(current, headerSize);
                    int stringCount = Marshal.ReadInt32(dataPtr);
                    if (stringCount >= 1)
                    {
                        // Массив указателей выровнен по размеру указателя (после dwStringCount + выравнивание).
                        IntPtr stringArray = IntPtr.Add(dataPtr, IntPtr.Size);
                        IntPtr firstString = Marshal.ReadIntPtr(stringArray);
                        if (firstString != IntPtr.Zero)
                            return Marshal.PtrToStringUni(firstString);
                    }
                }
                current = header.pNext;
            }
            return null;
        }

        private static bool IsHex40(string value)
        {
            if (value == null || value.Length != 40) return false;
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!hex) return false;
            }
            return true;
        }
    }
}
