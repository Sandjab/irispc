@echo off
setlocal

echo =======================================================
echo Compilation d'irispc (csc.exe natif, .NET Framework 4.8)
echo =======================================================

set CSC_PATH=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC_PATH%" set CSC_PATH=C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe
if not exist "%CSC_PATH%" (
    echo [ERREUR] Compilateur C# natif csc.exe introuvable.
    exit /b 1
)
echo Compilateur : %CSC_PATH%

set ROOT=%~dp0
set SRC=%ROOT%src
set VENDOR=%ROOT%vendor\KeePass-2.61.1
set OUT=%ROOT%build\Iris

if not exist "%VENDOR%\KeePass.exe" (
    echo [ERREUR] %VENDOR%\KeePass.exe introuvable : voir vendor\KeePass-2.61.1\README.md.
    exit /b 1
)
if not exist "%OUT%" mkdir "%OUT%"

rem --- irisd.exe ----------------------------------------------------------
rem Liste explicite des sources (meme liste IrisKit que test.bat).
set IRISKIT_SOURCES="%SRC%\IrisKit\IrisVersion.cs" "%SRC%\IrisKit\Json\JsonParser.cs" "%SRC%\IrisKit\Json\JsonObject.cs" "%SRC%\IrisKit\Json\JsonWriter.cs" "%SRC%\IrisKit\Models\HostName.cs" "%SRC%\IrisKit\Models\Secret.cs" "%SRC%\IrisKit\Models\MITMRule.cs" "%SRC%\IrisKit\Models\Alert.cs" "%SRC%\IrisKit\Models\Event.cs" "%SRC%\IrisKit\SecretStore\ISecretStore.cs" "%SRC%\IrisKit\Logging\Log.cs" "%SRC%\IrisKit\Logging\Redaction.cs" "%SRC%\IrisKit\Config\Config.cs" "%SRC%\IrisKit\Config\Backups.cs" "%SRC%\IrisKit\Config\ConfigStore.cs" "%SRC%\IrisKit\Events\EventRing.cs" "%SRC%\IrisKit\Events\EventsBus.cs" "%SRC%\IrisKit\Events\JsonlEventStore.cs" "%SRC%\IrisKit\Events\EventPipeline.cs" "%SRC%\IrisKit\SecretStore\InMemorySecretStore.cs" "%SRC%\IrisKit\SecretStore\SecretCache.cs" "%SRC%\IrisKit\SecretStore\EnvSecrets.cs" "%SRC%\IrisKit\SecretStore\SecretsMetaStore.cs"
set IRISD_SOURCES="%SRC%\irisd\Arguments.cs" "%SRC%\irisd\Program.cs"

"%CSC_PATH%" -nologo -codepage:65001 -target:exe -optimize+ -win32manifest:"%ROOT%app.manifest" -r:System.dll,System.Core.dll,System.Web.Extensions.dll,System.Security.dll -r:"%VENDOR%\KeePass.exe" -out:"%OUT%\irisd.exe" "%SRC%\AssemblyInfo.cs" %IRISKIT_SOURCES% %IRISD_SOURCES%
if %ERRORLEVEL% neq 0 (
    echo [ECHEC] Compilation de irisd.exe impossible.
    exit /b 1
)

rem --- Dossier portable ---------------------------------------------------
copy /y "%ROOT%config\irisd.exe.config" "%OUT%\irisd.exe.config" >nul || goto copy_failed
copy /y "%VENDOR%\KeePass.exe" "%OUT%\" >nul || goto copy_failed
copy /y "%VENDOR%\KeePass.exe.config" "%OUT%\" >nul || goto copy_failed
copy /y "%VENDOR%\KeePass.XmlSerializers.dll" "%OUT%\" >nul || goto copy_failed
copy /y "%VENDOR%\License.txt" "%OUT%\KeePass-License.txt" >nul || goto copy_failed

echo.
echo [SUCCES] Dossier portable assemble : %OUT%
exit /b 0

:copy_failed
echo [ECHEC] Copie des fichiers du dossier portable impossible (fichier verrouille ou chemin occupe) : %OUT%
exit /b 1
