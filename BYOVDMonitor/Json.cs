using System.Web.Script.Serialization;

namespace BYOVDMonitor
{
    // Обёртка над штатным сериализатором .NET Framework (без сторонних библиотек).
    // Список loldrivers большой, поэтому снимаем ограничение на длину входа.
    internal static class Json
    {
        private static JavaScriptSerializer Create()
        {
            var serializer = new JavaScriptSerializer();
            serializer.MaxJsonLength = int.MaxValue;
            serializer.RecursionLimit = 1000;
            return serializer;
        }

        // Сериализация объекта в строку JSON.
        public static string Serialize(object value)
        {
            return Create().Serialize(value);
        }

        // Десериализация в конкретный тип.
        public static T Deserialize<T>(string json)
        {
            return Create().Deserialize<T>(json);
        }

        // Десериализация в граф object[] / Dictionary<string,object> / примитивы.
        public static object DeserializeObject(string json)
        {
            return Create().DeserializeObject(json);
        }
    }
}
