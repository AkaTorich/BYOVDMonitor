using System;
using System.IO;
using System.Runtime.InteropServices;

namespace BYOVDMonitor
{
    // Проверка Authenticode-подписи файла через WinVerifyTrust (user mode, без своего драйвера).
    // Нужна как дополнительный слой к сверке с loldrivers: ловит драйверы, чью подпись Microsoft или
    // удостоверяющий центр ОТОЗВАЛИ, либо которые установлены без подписи / с нарушенной целостностью —
    // даже если конкретного хеша ещё нет в loldrivers.
    //
    // Отзыв проверяется ТОЛЬКО по локальному кешу CRL (WTD_CACHE_ONLY_URL_RETRIEVAL): без обращения в сеть,
    // чтобы проверка не подвисала и не шумела при офлайне. Вывод — короткая причина или null (всё чисто/
    // неизвестно). Уровень доверия у такого срабатывания — низкий (эвристика).
    internal static class SignatureChecker
    {
        // Возвращает причину, по которой подпись выглядит подозрительной, или null — если проверка не дала
        // явного негативного вердикта (доверенная подпись, либо неопределённость — тогда не шумим).
        public static string SuspiciousReason(string filePath)
        {
            try
            {
                if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath)) return null;

                int hr = Verify(filePath);
                switch ((uint)hr)
                {
                    case 0: // S_OK — доверенная подпись
                        return null;
                    case CERT_E_REVOKED:
                        return "certificate revoked";
                    case TRUST_E_EXPLICIT_DISTRUST:
                        return "explicitly distrusted";
                    case CERT_E_UNTRUSTEDROOT:
                        return "untrusted root";
                    case TRUST_E_BAD_DIGEST:
                        return "tampered (bad digest)";
                    case TRUST_E_NOSIGNATURE:
                    case TRUST_E_SUBJECT_FORM_UNKNOWN:
                    case TRUST_E_PROVIDER_UNKNOWN:
                        return "unsigned";
                    default:
                        // Прочие коды (просроченная подпись, неизвестный отзыв из-за офлайна и т. п.)
                        // не считаем поводом для тревоги — слишком шумно.
                        return null;
                }
            }
            catch
            {
                return null;
            }
        }

        private static int Verify(string filePath)
        {
            IntPtr pFilePath = Marshal.StringToHGlobalUni(filePath);
            IntPtr pFileInfo = IntPtr.Zero;
            try
            {
                var fileInfo = new WINTRUST_FILE_INFO
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)),
                    pcwszFilePath = pFilePath,
                    hFile = IntPtr.Zero,
                    pgKnownSubject = IntPtr.Zero
                };
                pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
                Marshal.StructureToPtr(fileInfo, pFileInfo, false);

                var data = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData = IntPtr.Zero,
                    dwUIChoice = WTD_UI_NONE,
                    fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN,
                    dwUnionChoice = WTD_CHOICE_FILE,
                    pFile = pFileInfo,
                    dwStateAction = WTD_STATEACTION_VERIFY,
                    hWVTStateData = IntPtr.Zero,
                    pwszURLReference = IntPtr.Zero,
                    // SAFER + отзыв только из кеша (без сети): проверка не подвисает в офлайне.
                    dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL,
                    dwUIContext = 0
                };

                Guid action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                int hr = WinVerifyTrust(IntPtr.Zero, ref action, ref data);

                // Освобождаем состояние провайдера доверия.
                data.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(IntPtr.Zero, ref action, ref data);

                return hr;
            }
            finally
            {
                if (pFileInfo != IntPtr.Zero) Marshal.FreeHGlobal(pFileInfo);
                if (pFilePath != IntPtr.Zero) Marshal.FreeHGlobal(pFilePath);
            }
        }

        // ===== WinAPI =====

        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
            new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        private const uint WTD_UI_NONE = 2;
        private const uint WTD_REVOKE_WHOLECHAIN = 1;
        private const uint WTD_CHOICE_FILE = 1;
        private const uint WTD_STATEACTION_VERIFY = 1;
        private const uint WTD_STATEACTION_CLOSE = 2;
        private const uint WTD_SAFER_FLAG = 0x100;
        private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

        // HRESULT-коды вердикта WinVerifyTrust.
        private const uint TRUST_E_NOSIGNATURE = 0x800B0100;
        private const uint TRUST_E_BAD_DIGEST = 0x80096010;
        private const uint TRUST_E_EXPLICIT_DISTRUST = 0x800B0111;
        private const uint TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003;
        private const uint TRUST_E_PROVIDER_UNKNOWN = 0x800B0001;
        private const uint CERT_E_REVOKED = 0x800B010C;
        private const uint CERT_E_UNTRUSTEDROOT = 0x800B0109;

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public IntPtr pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);
    }
}
