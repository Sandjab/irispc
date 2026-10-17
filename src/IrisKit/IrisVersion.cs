namespace IrisKit
{
    /// <summary>
    /// Version applicative affichée par irisd --version (et plus tard par iris et IrisApp).
    /// À faire évoluer ensemble avec src\AssemblyInfo.cs et app.manifest ; un test le vérifie.
    /// </summary>
    public static class IrisVersion
    {
        public const string Value = "0.1.0";
    }
}
