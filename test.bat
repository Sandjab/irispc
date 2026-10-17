@echo off
setlocal

echo =======================================================
echo Tests irispc (csc.exe natif, sans framework)
echo =======================================================

set CSC_PATH=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC_PATH%" set CSC_PATH=C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe
if not exist "%CSC_PATH%" (
    echo [ERREUR] Compilateur C# natif csc.exe introuvable.
    exit /b 1
)

set ROOT=%~dp0
set SRC=%ROOT%src
set VENDOR=%ROOT%vendor\KeePass-2.61.1
set TESTS=%ROOT%tests
set OUT_EXE=%TESTS%\Iris.Tests.exe

if not exist "%VENDOR%\KeePass.exe" (
    echo [ERREUR] %VENDOR%\KeePass.exe introuvable : voir vendor\KeePass-2.61.1\README.md.
    exit /b 1
)

rem Liste explicite des sources. src\irisd\Program.cs est remplace par le Main de tests\Tests.cs.
set IRISKIT_SOURCES="%SRC%\IrisKit\IrisVersion.cs" "%SRC%\IrisKit\DataDir.cs" "%SRC%\IrisKit\Json\JsonParser.cs" "%SRC%\IrisKit\Json\JsonObject.cs" "%SRC%\IrisKit\Json\JsonWriter.cs" "%SRC%\IrisKit\Models\HostName.cs" "%SRC%\IrisKit\Models\Secret.cs" "%SRC%\IrisKit\Models\MITMRule.cs" "%SRC%\IrisKit\Models\Alert.cs" "%SRC%\IrisKit\Models\Event.cs" "%SRC%\IrisKit\Logging\Log.cs" "%SRC%\IrisKit\Logging\Redaction.cs" "%SRC%\IrisKit\Config\Config.cs" "%SRC%\IrisKit\Config\Backups.cs" "%SRC%\IrisKit\Config\ConfigStore.cs" "%SRC%\IrisKit\Events\EventRing.cs" "%SRC%\IrisKit\Events\EventsBus.cs" "%SRC%\IrisKit\Events\JsonlEventStore.cs" "%SRC%\IrisKit\Events\EventPipeline.cs" "%SRC%\IrisKit\SecretStore\ISecretStore.cs" "%SRC%\IrisKit\SecretStore\InMemorySecretStore.cs" "%SRC%\IrisKit\SecretStore\SecretCache.cs" "%SRC%\IrisKit\SecretStore\EnvSecrets.cs" "%SRC%\IrisKit\SecretStore\SecretsMetaStore.cs" "%SRC%\IrisKit\SecretStore\KeePassVault.cs" "%SRC%\IrisKit\SecretStore\KeePassSecretStore.cs" "%SRC%\IrisKit\SecretStore\VaultSession.cs" "%SRC%\IrisKit\CA\CAMaterial.cs" "%SRC%\IrisKit\CA\CACrypto.cs" "%SRC%\IrisKit\CA\CAKeyStore.cs" "%SRC%\IrisKit\CA\CAManager.cs" "%SRC%\IrisKit\Proxy\HttpMessage.cs" "%SRC%\IrisKit\Proxy\HttpConnection.cs" "%SRC%\IrisKit\Proxy\HttpParser.cs"
set IRISD_SOURCES="%SRC%\irisd\Arguments.cs" "%SRC%\irisd\ExitCodes.cs" "%SRC%\irisd\IConsoleInput.cs" "%SRC%\irisd\Daemon.cs" "%SRC%\irisd\Entry.cs"
set TEST_SOURCES="%TESTS%\Check.cs" "%TESTS%\TestSupport.cs" "%TESTS%\Tests.cs" "%TESTS%\JsonTests.cs" "%TESTS%\ModelsTests.cs" "%TESTS%\LoggingTests.cs" "%TESTS%\ConfigTests.cs" "%TESTS%\EventsTests.cs" "%TESTS%\SecretStoreTests.cs" "%TESTS%\MetaStoreTests.cs" "%TESTS%\KeePassTests.cs" "%TESTS%\CATests.cs" "%TESTS%\DaemonTests.cs" "%TESTS%\HttpParserTests.cs"

"%CSC_PATH%" -nologo -codepage:65001 -target:exe -r:System.dll,System.Core.dll,System.Web.Extensions.dll,System.Security.dll -r:"%VENDOR%\KeePass.exe" -out:"%OUT_EXE%" "%SRC%\AssemblyInfo.cs" %IRISKIT_SOURCES% %IRISD_SOURCES% %TEST_SOURCES%
if %ERRORLEVEL% neq 0 (
    echo [ECHEC] Compilation des tests impossible.
    exit /b 1
)

rem KeePassLib est charge a l'execution depuis KeePass.exe place a cote de l'exe de tests.
copy /y "%VENDOR%\KeePass.exe" "%TESTS%\" >nul || goto copy_failed
copy /y "%VENDOR%\KeePass.XmlSerializers.dll" "%TESTS%\" >nul || goto copy_failed
copy /y "%ROOT%config\irisd.exe.config" "%OUT_EXE%.config" >nul || goto copy_failed

"%OUT_EXE%"
set RESULT=%ERRORLEVEL%
if %RESULT% equ 0 (
    echo [SUCCES] Tous les tests passent.
) else (
    echo [ECHEC] Des tests ont echoue.
)
exit /b %RESULT%

:copy_failed
echo [ECHEC] Copie de KeePass ou du .exe.config a cote de l'exe de tests impossible (fichier verrouille ou chemin occupe) : %TESTS%
exit /b 1
