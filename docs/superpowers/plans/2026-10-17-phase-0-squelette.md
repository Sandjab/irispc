# Phase 0 — Squelette du dépôt : plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Un dépôt qui compile un `irisd.exe` minimal (analyse des arguments, `--version`, `--help`) et un exécutable de tests avec le `csc.exe` natif, assemble le dossier portable `build\Iris\` avec KeePass, et passe vert en CI GitHub.

**Architecture:** Pattern ImPactHUD : un `.bat` par cible, liste explicite des sources, pas de framework de test (`tests\Tests.cs` porte son propre `Main` et remplace `src\irisd\Program.cs`). `KeePassLib` est référencé comme assembly depuis `vendor\KeePass-2.61.1\KeePass.exe` et copié à côté des exécutables. Le code produit se limite à la version applicative, à l'analyseur d'arguments de `irisd` (grammaire complète de la spec §7) et à un `Program.cs` qui n'exécute encore rien.

**Tech Stack:** C# 5, .NET Framework 4.8, `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`, KeePass 2.61.1 (`KeePassLib`), GitHub Actions `windows-latest`.

**Spec:** `docs/superpowers/specs/2026-10-17-socle-design.md` (§3 dossier portable, §7 daemon, §9 tests, §10 dépôt/build/CI, §11 phase 0). Contexte permanent : `CLAUDE.md` à la racine.

## Global Constraints

- Compilateur : `csc.exe` de `v4.0.30319` (Framework64, repli Framework) ; **C# 5 strict** : pas d'interpolation `$""`, pas de `?.`, pas de `nameof`, pas de `out var`, pas de tuples, pas de fonctions locales, pas de membres expression-bodied.
- Aucun SDK, aucun NuGet, aucun `dotnet`. Références autorisées : `System.dll, System.Core.dll, System.Web.Extensions.dll, System.Security.dll` et `vendor\KeePass-2.61.1\KeePass.exe`.
- Flags csc en forme `-flag` (la forme `/flag` est réécrite en chemin par Git Bash). Ajout de `-codepage:65001` : les sources sont en UTF-8 sans BOM et contiennent des accents.
- Liste **explicite** de sources dans chaque `.bat`, pas de glob. `%~dp0` pour tous les chemins, guillemets systématiques.
- Textes utilisateur en **français** ; identifiants, options CLI, clés JSON en anglais, identiques à IRIS.
- Version applicative `0.1.0` portée **ensemble** par `src\AssemblyInfo.cs` (`0.1.0.0`), `app.manifest` (`0.1.0.0`) et `IrisKit.IrisVersion.Value` (`0.1.0`).
- Codes de sortie de `irisd` (spec §7) : 0 normal, 1 données ou config (et aide sans `--foreground`), 2 coffre, 3 port, 4 argument invalide.
- Dossier portable `build\Iris\` : exe, `.exe.config`, `KeePass.exe`, `KeePass.exe.config`, `KeePass.XmlSerializers.dll`. Jamais commité.
- Aucun test n'ouvre une base KeePass utilisateur ; la phase 0 n'ouvre aucune base du tout.
- Sécurité (CLAUDE.md d'IRIS §6, spec §8) : aucune valeur de secret ni mot de passe dans les arguments, l'environnement, les logs ; la phase 0 n'en manipule aucun et n'introduit aucun mode qui le permettrait.
- Git : branche `feat/phase-0-socle` (déjà créée), commits conventionnels, pas de push sur `main`, PR avec checklist de smoke testing, merge en squash **uniquement après confirmation explicite de l'utilisateur**.
- Fichiers `.bat` en CRLF (`.gitattributes`), sources `.cs` en LF.

## Review Focus

1. **`--data` suivi d'une valeur qui commence par `--` ou vide** : refus avec code 4, jamais un dossier nommé `--foreground` créé en silence. Test dans la tâche 4.
2. **Option répétée** (`--data a --data b`) : refus avec code 4, pas de « dernier gagne » silencieux. Test dans la tâche 4.
3. **Accents dans les sources sans BOM** : sans `-codepage:65001`, csc lit les `.cs` en Windows-1252 et les messages français sortent en mojibake. Test dans la tâche 4 (le texte d'usage contient `\u00e9`).
4. **Scripts lancés depuis un autre répertoire courant** (CI, `C:\`) : tous les chemins passent par `%~dp0`. Vérification dans les tâches 3 et 5.
5. **Dépôt cloné dans un chemin avec espace** : guillemets sur chaque chemin des `.bat`. Vérification dans la tâche 5 (copie du dépôt sous `%TEMP%\irispc test\`).

---

## Structure des fichiers de la phase 0

| Fichier | Responsabilité |
|---|---|
| `.gitignore` | exclut `build\`, les exécutables de test, les copies de KeePass dans `tests\`, `data\` |
| `.gitattributes` | CRLF pour `.bat`, binaires pour `.exe`, `.dll`, `.chm` |
| `README.md` | présentation courte, état « en construction », liens vers IRIS et la spec |
| `app.manifest` | PerMonitorV2, asInvoker, version `0.1.0.0` ; appliqué à `irisd.exe` dès maintenant |
| `src\AssemblyInfo.cs` | attributs d'assembly, version `0.1.0.0` |
| `src\IrisKit\IrisVersion.cs` | constante `IrisVersion.Value = "0.1.0"` |
| `src\irisd\Arguments.cs` | `Arguments.Parse(string[])`, `Arguments.Usage()`, `ArgumentsException` |
| `src\irisd\Program.cs` | `Main` : aide, version, codes de sortie ; aucun daemon encore |
| `config\irisd.exe.config` | runtime v4.0, bindingRedirect KeePass, `enforceFIPSPolicy=false` |
| `vendor\KeePass-2.61.1\` | `KeePass.exe`, `KeePass.exe.config`, `KeePass.XmlSerializers.dll`, `License.txt`, `README.md` |
| `tests\Check.cs` | assertions maison, compteur, liste des échecs, `Run`, `Summary` |
| `tests\Tests.cs` | `Main` des tests ; tests de la phase 0 |
| `build.bat` | compile `irisd.exe`, assemble `build\Iris\` |
| `test.bat` | compile `tests\Iris.Tests.exe`, copie KeePass à côté, exécute, propage le code |
| `.github\workflows\ci.yml` | `windows-latest` : `test.bat` puis `build.bat`, artefact `build\Iris` |

Espaces de noms : `IrisKit` (bibliothèque), `Irisd` (daemon), `Iris.Tests` (tests).

Les fichiers KeePass d'origine sont dans le scratchpad de la session de conception :
`C:\Users\jp\AppData\Local\Temp\claude\D--Dev-irispc\77232ace-bae7-4605-b619-4150ff9b3382\scratchpad\kp-dl\` (`KeePass-2.61.1.zip` et `extract\`). Si ce dossier n'existe plus, télécharger `KeePass-2.61.1.zip` depuis `https://sourceforge.net/projects/keepass/files/KeePass%202.x/2.61.1/` **avec un navigateur** (SourceForge sert un captcha aux clients non-navigateur), dans un dossier vide du scratchpad, et vérifier le SHA-256 du zip : `3952354db9b117e906f7cd4f9f5591065b95186472370da47f46f3e246fea864`.

---

### Task 1: Squelette du dépôt (métadonnées, manifeste, version)

**Files:**
- Create: `.gitignore`
- Modify: `.gitattributes`
- Create: `README.md`
- Create: `app.manifest`
- Create: `src\AssemblyInfo.cs`
- Create: `src\IrisKit\IrisVersion.cs`

**Interfaces:**
- Consumes: rien.
- Produces: `IrisKit.IrisVersion.Value` (`public const string`, `"0.1.0"`) ; `app.manifest` utilisé par `build.bat` (tâche 5) ; `src\AssemblyInfo.cs` compilé dans chaque exe.

- [ ] **Step 1: Écrire `.gitignore`**

```gitignore
# Sorties de build (dossier portable assemblé par build.bat)
build/

# Exécutable de tests et fichiers copiés à côté par test.bat
tests/*.exe
tests/*.exe.config
tests/*.pdb
tests/KeePass.exe
tests/KeePass.XmlSerializers.dll
tests/out/

# Données locales d'une instance lancée depuis le dépôt
data/

# Divers
*.pdb
*.suo
*.user
Thumbs.db
```

- [ ] **Step 2: Compléter `.gitattributes`**

Remplacer le contenu par :

```gitattributes
# Auto detect text files and perform LF normalization
* text=auto

# Scripts cmd : CRLF obligatoire
*.bat text eol=crlf

# Binaires redistribués (vendor\KeePass-2.61.1)
*.exe binary
*.dll binary
*.chm binary
*.ico binary
*.png binary
```

- [ ] **Step 3: Écrire `README.md`**

````markdown
# irispc — IRIS pour Windows

[![CI](https://github.com/Sandjab/irispc/actions/workflows/ci.yml/badge.svg)](https://github.com/Sandjab/irispc/actions/workflows/ci.yml)

Portage Windows d'[IRIS](https://github.com/Sandjab/Iris) (Interception · Resolution · Injection · Substitution), le broker de credentials local pour agents IA : un proxy HTTPS local substitue les placeholders `{{kc:NAME}}` par les vraies valeurs d'un coffre, et l'outil hôte (Claude Code, `gh`, `curl`, serveurs MCP) ne voit jamais les secrets.

**État : en construction.** La phase 0 (squelette, build, CI) est en cours ; rien n'est utilisable encore.

- Coffre : base KeePass portable (`.kdbx`), mot de passe maître saisi une fois par session.
- Compilation : C# avec le `csc.exe` natif de Windows, sans SDK ni NuGet (`build.bat`, `test.bat`).
- Distribution : dossier portable (zip), aucune installation.
- Documentation : `https://sandjab.github.io/irispc` (à venir).

## Construire

```bat
test.bat     compile et exécute les tests (tests\Iris.Tests.exe)
build.bat    compile irisd.exe et assemble le dossier portable build\Iris\
```

## Conception

- `CLAUDE.md` — contraintes du portage et correspondances macOS → Windows.
- `docs/superpowers/specs/` — specs par lot ; `docs/superpowers/plans/` — plans d'implémentation.

## Licence

MIT (voir `LICENSE`). KeePass est redistribué sous GPLv2 (voir `vendor/KeePass-2.61.1/`).
````

- [ ] **Step 4: Écrire `app.manifest`**

```xml
<?xml version="1.0" encoding="utf-8"?>
<assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1">
  <assemblyIdentity version="0.1.0.0" name="irispc" type="win32" />
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
    <security>
      <requestedPrivileges xmlns="urn:schemas-microsoft-com:asm.v3">
        <!-- Jamais d'élévation : le CA s'installe dans CurrentUser\Root. -->
        <requestedExecutionLevel level="asInvoker" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <!-- Rendu net sur chaque écran (IrisApp reconstruit son interface sur WM_DPICHANGED). -->
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <!-- Windows 10 / 11 -->
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}" />
    </application>
  </compatibility>
</assembly>
```

- [ ] **Step 5: Écrire `src\AssemblyInfo.cs`**

```csharp
using System.Reflection;

// Version applicative : à faire évoluer ensemble avec app.manifest et IrisKit.IrisVersion.Value.
[assembly: AssemblyTitle("irispc")]
[assembly: AssemblyDescription("IRIS pour Windows : broker de credentials local (proxy HTTPS MITM, coffre KeePass)")]
[assembly: AssemblyProduct("irispc")]
[assembly: AssemblyCompany("Sandjab")]
[assembly: AssemblyCopyright("Copyright (c) 2026 Jean-Paul Gavini. Licence MIT.")]
[assembly: AssemblyVersion("0.1.0.0")]
[assembly: AssemblyFileVersion("0.1.0.0")]
```

- [ ] **Step 6: Écrire `src\IrisKit\IrisVersion.cs`**

```csharp
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
```

- [ ] **Step 7: Vérifier que les deux sources compilent**

Depuis Git Bash, à la racine du dépôt :

```bash
mkdir -p /tmp/irispc-t1 && /c/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe -nologo -codepage:65001 -target:library -out:/tmp/irispc-t1/v.dll src/AssemblyInfo.cs src/IrisKit/IrisVersion.cs && echo COMPILE_OK
```

Attendu : `COMPILE_OK`, aucun avertissement.

- [ ] **Step 8: Vérifier la normalisation des fins de ligne et l'état git**

```bash
git add --renormalize . && git status --short
```

Attendu : les six fichiers de la tâche, rien d'autre (pas de `build/`, pas de `tests/*.exe`).

- [ ] **Step 9: Commit**

```bash
git add .gitignore .gitattributes README.md app.manifest src/AssemblyInfo.cs src/IrisKit/IrisVersion.cs
git commit -m "chore: squelette du dépôt, manifeste et version 0.1.0

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: KeePass 2.61.1 dans `vendor\`

**Files:**
- Create: `vendor\KeePass-2.61.1\KeePass.exe` (copie)
- Create: `vendor\KeePass-2.61.1\KeePass.exe.config` (copie)
- Create: `vendor\KeePass-2.61.1\KeePass.XmlSerializers.dll` (copie)
- Create: `vendor\KeePass-2.61.1\License.txt` (copie)
- Create: `vendor\KeePass-2.61.1\README.md`

**Interfaces:**
- Consumes: le dossier `extract\` du scratchpad (voir « Structure des fichiers »).
- Produces: `vendor\KeePass-2.61.1\KeePass.exe`, référencé par `-r:` dans `test.bat` (tâche 3) et `build.bat` (tâche 5), et copié à côté des exécutables.

- [ ] **Step 1: Copier les quatre fichiers**

```bash
SRC="/c/Users/jp/AppData/Local/Temp/claude/D--Dev-irispc/77232ace-bae7-4605-b619-4150ff9b3382/scratchpad/kp-dl/extract"
mkdir -p vendor/KeePass-2.61.1
cp "$SRC/KeePass.exe" "$SRC/KeePass.exe.config" "$SRC/KeePass.XmlSerializers.dll" "$SRC/License.txt" vendor/KeePass-2.61.1/
ls -la vendor/KeePass-2.61.1/
```

Attendu : `KeePass.exe` 3 265 880 octets, `KeePass.XmlSerializers.dll` 446 872 octets, `KeePass.exe.config` 761 octets, `License.txt` 18 710 octets.

- [ ] **Step 2: Vérifier les empreintes SHA-256**

```bash
cd vendor/KeePass-2.61.1 && sha256sum KeePass.exe KeePass.exe.config KeePass.XmlSerializers.dll License.txt; cd ../..
```

Attendu, exactement :

```
04d29636c393f0c1fc99ff739295494be3adefded93271e44591e8e300225a5a  KeePass.exe
0bc2bd2b3aad3509c8a49cf053347f01a095cd07b4a52f141d41b1cfdf93fea2  KeePass.exe.config
32f8badaa69700547a605314481d64d38335e7fe09e51e575d4197837d857ac8  KeePass.XmlSerializers.dll
05646d0e8b70da13b0c0d81aaba2c0526be2e8ffdbcb7322d9c4061d27e2143e  License.txt
```

Toute différence = arrêter, ne pas commiter, signaler.

- [ ] **Step 3: Écrire `vendor\KeePass-2.61.1\README.md`**

```markdown
# KeePass 2.61.1 (portable) — fichiers redistribués

Ces fichiers proviennent de l'archive portable officielle **KeePass-2.61.1.zip**
(`https://sourceforge.net/projects/keepass/files/KeePass%202.x/2.61.1/`), téléchargée le 2026-10-17.

| Fichier | SHA-256 |
|---|---|
| `KeePass-2.61.1.zip` (archive d'origine, non commitée) | `3952354db9b117e906f7cd4f9f5591065b95186472370da47f46f3e246fea864` |
| `KeePass.exe` | `04d29636c393f0c1fc99ff739295494be3adefded93271e44591e8e300225a5a` |
| `KeePass.exe.config` | `0bc2bd2b3aad3509c8a49cf053347f01a095cd07b4a52f141d41b1cfdf93fea2` |
| `KeePass.XmlSerializers.dll` | `32f8badaa69700547a605314481d64d38335e7fe09e51e575d4197837d857ac8` |
| `License.txt` | `05646d0e8b70da13b0c0d81aaba2c0526be2e8ffdbcb7322d9c4061d27e2143e` |

## Pourquoi ces fichiers sont dans le dépôt

- `KeePassLib` (lecture et écriture des bases `.kdbx`) est **compilé dans `KeePass.exe`** ; l'archive portable ne contient pas de `KeePassLib.dll`. irispc référence `KeePass.exe` au build (`-r:vendor\KeePass-2.61.1\KeePass.exe`), comme le fait un plugin KeePass, et le copie à côté de ses exécutables.
- SourceForge sert un captcha aux clients non-navigateur : aucun téléchargement au build ni en CI. Les fichiers sont donc commités tels quels et vérifiés par empreinte.
- L'utilisateur peut ouvrir `data\iris.kdbx` avec ce même `KeePass.exe` pour auditer le coffre.

## Fichiers volontairement non repris

`KeePassLibN.*.dll` (accélération native optionnelle), `ShInstUtil.exe`, `KeePass.chm`, `Languages\`, `Plugins\`, `XSL\` : inutiles au broker.

## Licence

KeePass est distribué sous **GNU GPL v2** (voir `License.txt`). irispc est sous licence MIT ; le zip combiné distribué en release est de ce fait soumis à la GPL, sans effet pour un projet ouvert.

## Mettre à jour KeePass

1. Télécharger le nouveau zip portable avec un navigateur, vérifier son SHA-256 publié.
2. Remplacer les quatre fichiers, mettre à jour ce tableau et le nom du dossier.
3. Reporter la `bindingRedirect` de `KeePass.exe.config` dans `config\*.exe.config` (`oldVersion` / `newVersion`).
4. Mettre à jour les chemins `vendor\KeePass-<version>` dans `build.bat`, `test.bat` et `CLAUDE.md`.
```

- [ ] **Step 4: Vérifier que git voit les binaires comme binaires**

```bash
git add vendor && git diff --cached --numstat -- vendor
```

Attendu : les lignes de `KeePass.exe` et `KeePass.XmlSerializers.dll` affichent `-	-	vendor/...` (binaire, pas de normalisation) ; les trois fichiers texte ont des comptes de lignes.

- [ ] **Step 5: Commit**

```bash
git commit -m "chore(vendor): KeePass 2.61.1 portable (KeePassLib) avec empreintes SHA-256

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: Harnais de tests, `config\irisd.exe.config` et `test.bat`

**Files:**
- Create: `tests\Check.cs`
- Create: `tests\Tests.cs`
- Create: `config\irisd.exe.config`
- Create: `test.bat`

**Interfaces:**
- Consumes: `IrisKit.IrisVersion.Value` (tâche 1), `vendor\KeePass-2.61.1\KeePass.exe` (tâche 2).
- Produces: `Iris.Tests.Check` (`True(bool, string)`, `Eq<T>(T expected, T actual, string)`, `Throws<TException>(Action, string) : TException`, `Run(string, Action)`, `Summary() : int`, compteur `Checks`) ; `Iris.Tests.TestMain.Main()` ; `test.bat` à compléter par les tâches suivantes (liste de sources) ; `config\irisd.exe.config` copié par `build.bat` (tâche 5).

- [ ] **Step 1: Écrire `tests\Check.cs`**

```csharp
using System;
using System.Collections.Generic;

namespace Iris.Tests
{
    /// <summary>Échec d'une vérification : le message décrit l'écart.</summary>
    public sealed class CheckException : Exception
    {
        public CheckException(string message) : base(message) { }
    }

    /// <summary>
    /// Assertions maison, sans framework : chaque vérification incrémente Checks,
    /// chaque test en échec est listé dans Failures, Summary() rend 0 ou 1.
    /// </summary>
    public static class Check
    {
        public static int Checks;
        public static int Passed;
        public static readonly List<string> Failures = new List<string>();

        public static void True(bool condition, string what)
        {
            Checks++;
            if (!condition) throw new CheckException(what);
        }

        public static void Eq<T>(T expected, T actual, string what)
        {
            Checks++;
            if (!EqualityComparer<T>.Default.Equals(expected, actual))
                throw new CheckException(what + " : attendu <" + Show(expected) + ">, obtenu <" + Show(actual) + ">");
        }

        /// <summary>Vérifie qu'une exception du type attendu est levée et la rend pour inspection.</summary>
        public static TException Throws<TException>(Action action, string what) where TException : Exception
        {
            Checks++;
            try
            {
                action();
            }
            catch (TException ex)
            {
                return ex;
            }
            catch (Exception ex)
            {
                throw new CheckException(what + " : " + ex.GetType().Name + " levée au lieu de "
                    + typeof(TException).Name + " (" + ex.Message + ")");
            }
            throw new CheckException(what + " : aucune exception, " + typeof(TException).Name + " attendue");
        }

        public static void Run(string name, Action test)
        {
            try
            {
                test();
                Passed++;
                Console.WriteLine("  OK   " + name);
            }
            catch (Exception ex)
            {
                Failures.Add(name + " : " + ex.Message);
                Console.WriteLine("  FAIL " + name);
                Console.WriteLine("       " + ex.Message);
            }
        }

        public static int Summary()
        {
            Console.WriteLine();
            Console.WriteLine("{0} test(s) réussi(s), {1} échec(s), {2} vérification(s)", Passed, Failures.Count, Checks);
            foreach (string failure in Failures) Console.WriteLine("  - " + failure);
            return Failures.Count == 0 ? 0 : 1;
        }

        private static string Show(object value)
        {
            return value == null ? "null" : value.ToString();
        }
    }
}
```

- [ ] **Step 2: Écrire `tests\Tests.cs` avec les trois premiers tests**

```csharp
using System;
using System.IO;
using System.Reflection;
using System.Text;
using IrisKit;

namespace Iris.Tests
{
    /// <summary>
    /// Harnais de tests sans framework : compilé et exécuté par test.bat avec le csc.exe natif.
    /// Remplace src\irisd\Program.cs ; chaque test est une méthode, Summary() donne le code de sortie.
    /// </summary>
    public static class TestMain
    {
        public static int Main()
        {
            Console.OutputEncoding = Encoding.UTF8;

            Check.Run("Check : Eq et Throws signalent les écarts", Check_SelfTest);
            Check.Run("Version : constante, assembly et manifeste cohérents", Version_Consistent);
            Check.Run("KeePassLib : chargeable depuis KeePass.exe 2.61.1", KeePassLib_Loads);

            return Check.Summary();
        }

        // ---- Harnais ---------------------------------------------------

        private static void Check_SelfTest()
        {
            CheckException ex = Check.Throws<CheckException>(delegate { Check.Eq(1, 2, "un contre deux"); }, "Eq détecte l'écart");
            Check.True(ex.Message.Contains("attendu <1>") && ex.Message.Contains("obtenu <2>"), "le message cite les deux valeurs");
            Check.Throws<CheckException>(delegate { Check.True(false, "faux"); }, "True(false) lève");
            Check.Throws<CheckException>(
                delegate { Check.Throws<InvalidOperationException>(delegate { }, "rien"); },
                "Throws sans exception lève");
            Check.Throws<CheckException>(
                delegate { Check.Throws<InvalidOperationException>(delegate { throw new ArgumentException("x"); }, "autre"); },
                "Throws avec un autre type lève");
        }

        // ---- Version ---------------------------------------------------

        private static void Version_Consistent()
        {
            Version assembly = typeof(IrisVersion).Assembly.GetName().Version;
            Check.Eq(IrisVersion.Value + ".0", assembly.ToString(), "AssemblyVersion = IrisVersion.Value + .0");

            string manifest = File.ReadAllText(RepoPath("app.manifest"));
            Check.True(manifest.Contains("version=\"" + IrisVersion.Value + ".0\""), "app.manifest porte la même version");
        }

        // ---- KeePass ---------------------------------------------------

        private static void KeePassLib_Loads()
        {
            KeePassLib.PwDatabase db = new KeePassLib.PwDatabase();
            Check.True(!db.IsOpen, "base neuve fermée");
            Check.Eq("2.61.1.0", typeof(KeePassLib.PwDatabase).Assembly.GetName().Version.ToString(), "version de l'assembly KeePass");
        }

        // ---- Outils ----------------------------------------------------

        /// <summary>Chemin d'un fichier du dépôt, depuis l'emplacement de Iris.Tests.exe (tests\).</summary>
        private static string RepoPath(string relative)
        {
            string testsDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            return Path.GetFullPath(Path.Combine(testsDir, "..", relative));
        }
    }
}
```

- [ ] **Step 3: Écrire `config\irisd.exe.config`**

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <startup>
    <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.8" />
  </startup>
  <runtime>
    <!-- Repris de KeePass.exe.config : à faire évoluer avec la version embarquée dans vendor\ -->
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <dependentAssembly>
        <assemblyIdentity name="KeePass" publicKeyToken="fed2ed7716aecf5c" culture="neutral" />
        <bindingRedirect oldVersion="2.0.9.0-2.61.0.127" newVersion="2.61.1.0" />
      </dependentAssembly>
    </assemblyBinding>
    <!-- KeePassLib refuse de fonctionner sous politique FIPS -->
    <enforceFIPSPolicy enabled="false" />
  </runtime>
</configuration>
```

- [ ] **Step 4: Écrire `test.bat`**

```bat
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
set IRISKIT_SOURCES="%SRC%\IrisKit\IrisVersion.cs"
set IRISD_SOURCES=
set TEST_SOURCES="%TESTS%\Check.cs" "%TESTS%\Tests.cs"

"%CSC_PATH%" -nologo -codepage:65001 -target:exe -r:System.dll,System.Core.dll,System.Web.Extensions.dll,System.Security.dll -r:"%VENDOR%\KeePass.exe" -out:"%OUT_EXE%" "%SRC%\AssemblyInfo.cs" %IRISKIT_SOURCES% %IRISD_SOURCES% %TEST_SOURCES%
if %ERRORLEVEL% neq 0 (
    echo [ECHEC] Compilation des tests impossible.
    exit /b 1
)

rem KeePassLib est charge a l'execution depuis KeePass.exe place a cote de l'exe de tests.
copy /y "%VENDOR%\KeePass.exe" "%TESTS%\" >nul
copy /y "%VENDOR%\KeePass.XmlSerializers.dll" "%TESTS%\" >nul
copy /y "%ROOT%config\irisd.exe.config" "%OUT_EXE%.config" >nul

"%OUT_EXE%"
set RESULT=%ERRORLEVEL%
if %RESULT% equ 0 (
    echo [SUCCES] Tous les tests passent.
) else (
    echo [ECHEC] Des tests ont echoue.
)
exit /b %RESULT%
```

Puis forcer les fins de ligne CRLF sur disque (git les imposera au checkout, pas à la création) :

```bash
sed -i 's/\r*$/\r/' test.bat
```

- [ ] **Step 5: Exécuter `test.bat` depuis la racine**

```bash
cmd //c test.bat; echo "EXIT=$?"
```

Attendu : trois lignes `OK`, `3 test(s) réussi(s), 0 échec(s), 8 vérification(s)`, `[SUCCES]`, `EXIT=0`. Les accents de `réussi(s)` doivent s'afficher correctement (sinon `-codepage:65001` manque).

- [ ] **Step 6: Vérifier le lancement depuis un autre répertoire courant**

```bash
(cd /c/ && cmd //c "D:\Dev\irispc\test.bat"); echo "EXIT=$?"
```

Attendu : même sortie, `EXIT=0`.

- [ ] **Step 7: Vérifier la propagation d'un échec**

Ajouter temporairement dans `Version_Consistent`, en première ligne : `Check.True(false, "échec volontaire");` puis :

```bash
cmd //c test.bat; echo "EXIT=$?"
```

Attendu : une ligne `FAIL Version : ...` suivie de `échec volontaire`, `[ECHEC]`, `EXIT=1`. Retirer la ligne, relancer, `EXIT=0`.

- [ ] **Step 8: Vérifier que rien de généré n'est suivi par git**

```bash
git status --short
```

Attendu : `config/`, `test.bat`, `tests/Check.cs`, `tests/Tests.cs` seulement ; ni `tests/Iris.Tests.exe`, ni `tests/KeePass.exe`, ni `tests/Iris.Tests.exe.config`.

- [ ] **Step 9: Commit**

```bash
git add config/irisd.exe.config test.bat tests/Check.cs tests/Tests.cs
git commit -m "test: harnais sans framework, test.bat et irisd.exe.config

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: `Arguments` du daemon (grammaire de la spec §7), en TDD

**Files:**
- Create: `src\irisd\Arguments.cs`
- Modify: `tests\Tests.cs`
- Modify: `test.bat` (ligne `set IRISD_SOURCES=`)

**Interfaces:**
- Consumes: `Iris.Tests.Check` (tâche 3).
- Produces: `Irisd.Arguments` avec `static Arguments Parse(string[] args)` (lève `Irisd.ArgumentsException`), `static string Usage()`, propriétés `bool Foreground`, `bool ShowVersion`, `bool ShowHelp`, `bool InMemorySecrets`, `bool InMemoryCa`, `string Data` (null = défaut), `string LogLevel` (null = défaut), `static readonly string[] LogLevels`. Utilisé par `Program.cs` (tâche 5) et repris par la phase 1.

- [ ] **Step 1: Ajouter les tests d'arguments dans `tests\Tests.cs`**

Dans `Main`, après la ligne `KeePassLib`, ajouter :

```csharp
            Check.Run("Arguments : --foreground seul", Arguments_ForegroundOnly);
            Check.Run("Arguments : toutes les options de la spec §7", Arguments_AllOptions);
            Check.Run("Arguments : --version, --help, vide", Arguments_VersionHelpEmpty);
            Check.Run("Arguments : option inconnue, casse, positionnel", Arguments_Unknown);
            Check.Run("Arguments : valeur manquante ou vide pour --data et --log-level", Arguments_MissingValue);
            Check.Run("Arguments : niveau de log inconnu", Arguments_BadLogLevel);
            Check.Run("Arguments : option répétée refusée", Arguments_Duplicate);
            Check.Run("Arguments : usage en français, accents intacts", Arguments_UsageText);
```

Ajouter `using Irisd;` en tête du fichier, puis les méthodes, avant la section `Outils` :

```csharp
        // ---- Arguments de irisd ----------------------------------------

        private static void Arguments_ForegroundOnly()
        {
            Arguments a = Arguments.Parse(new[] { "--foreground" });
            Check.True(a.Foreground, "Foreground");
            Check.True(!a.ShowVersion && !a.ShowHelp && !a.InMemorySecrets && !a.InMemoryCa, "autres drapeaux à faux");
            Check.Eq(null, a.Data, "Data par défaut");
            Check.Eq(null, a.LogLevel, "LogLevel par défaut");
        }

        private static void Arguments_AllOptions()
        {
            Arguments a = Arguments.Parse(new[] {
                "--foreground", "--data", "D:\\iris data", "--in-memory-secrets", "--in-memory-ca", "--log-level", "debug" });
            Check.True(a.Foreground && a.InMemorySecrets && a.InMemoryCa, "drapeaux");
            Check.Eq("D:\\iris data", a.Data, "Data conservé tel quel, espace compris");
            Check.Eq("debug", a.LogLevel, "LogLevel");
            foreach (string level in Arguments.LogLevels)
                Check.Eq(level, Arguments.Parse(new[] { "--log-level", level }).LogLevel, "niveau " + level);
            Check.Eq(4, Arguments.LogLevels.Length, "quatre niveaux : debug, info, warning, error");
        }

        private static void Arguments_VersionHelpEmpty()
        {
            Check.True(Arguments.Parse(new[] { "--version" }).ShowVersion, "--version");
            Check.True(Arguments.Parse(new[] { "--help" }).ShowHelp, "--help");
            Arguments empty = Arguments.Parse(new string[0]);
            Check.True(!empty.Foreground && !empty.ShowVersion && !empty.ShowHelp, "vide : rien de demandé");
        }

        private static void Arguments_Unknown()
        {
            ArgumentsException ex = Check.Throws<ArgumentsException>(
                delegate { Arguments.Parse(new[] { "--foreground", "--verbose" }); }, "option inconnue");
            Check.True(ex.Message.Contains("--verbose"), "le message cite l'option");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--Foreground" }); }, "sensible à la casse");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "foreground" }); }, "positionnel refusé");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "-f" }); }, "forme courte refusée");
        }

        private static void Arguments_MissingValue()
        {
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--foreground", "--data" }); }, "--data en fin");
            ArgumentsException ex = Check.Throws<ArgumentsException>(
                delegate { Arguments.Parse(new[] { "--data", "--foreground" }); }, "--data suivi d'une option");
            Check.True(ex.Message.Contains("--data"), "le message cite --data");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--data", "" }); }, "--data vide");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--log-level" }); }, "--log-level en fin");
        }

        private static void Arguments_BadLogLevel()
        {
            ArgumentsException ex = Check.Throws<ArgumentsException>(
                delegate { Arguments.Parse(new[] { "--log-level", "verbose" }); }, "niveau inconnu");
            Check.True(ex.Message.Contains("verbose") && ex.Message.Contains("debug"), "le message cite la valeur et les niveaux attendus");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--log-level", "INFO" }); }, "casse des niveaux");
        }

        private static void Arguments_Duplicate()
        {
            ArgumentsException ex = Check.Throws<ArgumentsException>(
                delegate { Arguments.Parse(new[] { "--data", "a", "--data", "b" }); }, "--data répété");
            Check.True(ex.Message.Contains("--data"), "le message cite l'option");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--foreground", "--foreground" }); }, "--foreground répété");
        }

        private static void Arguments_UsageText()
        {
            string usage = Arguments.Usage();
            Check.True(usage.StartsWith("Usage : irisd --foreground"), "première ligne");
            foreach (string option in new[] { "--foreground", "--data", "--in-memory-secrets", "--in-memory-ca", "--log-level", "--version", "--help" })
                Check.True(usage.Contains(option), "usage cite " + option);
            Check.True(usage.Contains("d\u00e9faut"), "accent é intact (codepage 65001)");
            Check.True(usage.Contains("DEBUG"), "les modes in-memory sont marqués DEBUG");
        }
```

- [ ] **Step 2: Lancer les tests pour constater l'échec**

```bash
cmd //c test.bat; echo "EXIT=$?"
```

Attendu : erreurs csc `CS0246 ... 'Arguments'` / `CS0246 ... 'Irisd'`, `[ECHEC] Compilation des tests impossible.`, `EXIT=1`.

- [ ] **Step 3: Écrire `src\irisd\Arguments.cs`**

```csharp
using System;
using System.Collections.Generic;

namespace Irisd
{
    /// <summary>Ligne de commande invalide : message en français, code de sortie 4 (spec §7).</summary>
    public sealed class ArgumentsException : Exception
    {
        public ArgumentsException(string message) : base(message) { }
    }

    /// <summary>
    /// Options de irisd (spec socle §7). Analyse stricte : options exactes et sensibles à la casse,
    /// pas de forme courte, pas de positionnel, pas de répétition, valeur obligatoire pour --data et --log-level.
    /// Aucun secret ni mot de passe ne passe jamais par la ligne de commande.
    /// </summary>
    public sealed class Arguments
    {
        public static readonly string[] LogLevels = { "debug", "info", "warning", "error" };

        public bool Foreground { get; private set; }
        public bool ShowVersion { get; private set; }
        public bool ShowHelp { get; private set; }
        public bool InMemorySecrets { get; private set; }
        public bool InMemoryCa { get; private set; }
        /// <summary>Dossier des données ; null = data\ à côté de l'exécutable.</summary>
        public string Data { get; private set; }
        /// <summary>Niveau de log ; null = valeur de config.json.</summary>
        public string LogLevel { get; private set; }

        public static Arguments Parse(string[] args)
        {
            Arguments result = new Arguments();
            HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                if (!arg.StartsWith("--", StringComparison.Ordinal))
                    throw new ArgumentsException("argument inattendu : " + arg);
                if (!seen.Add(arg))
                    throw new ArgumentsException("option répétée : " + arg);
                switch (arg)
                {
                    case "--foreground": result.Foreground = true; break;
                    case "--version": result.ShowVersion = true; break;
                    case "--help": result.ShowHelp = true; break;
                    case "--in-memory-secrets": result.InMemorySecrets = true; break;
                    case "--in-memory-ca": result.InMemoryCa = true; break;
                    case "--data":
                        result.Data = ValueOf(args, ref i);
                        break;
                    case "--log-level":
                        result.LogLevel = ValueOf(args, ref i);
                        if (Array.IndexOf(LogLevels, result.LogLevel) < 0)
                            throw new ArgumentsException("niveau de log inconnu : " + result.LogLevel
                                + " (attendu : " + string.Join(", ", LogLevels) + ")");
                        break;
                    default:
                        throw new ArgumentsException("option inconnue : " + arg);
                }
            }
            return result;
        }

        public static string Usage()
        {
            return string.Join(Environment.NewLine, new[] {
                "Usage : irisd --foreground [--data <dossier>] [--in-memory-secrets] [--in-memory-ca] [--log-level <niveau>]",
                "        irisd --version | --help",
                "",
                "Options :",
                "  --foreground           lance le daemon en avant-plan (obligatoire dans cette version)",
                "  --data <dossier>       dossier des données (défaut : data\\ à côté de irisd.exe)",
                "  --in-memory-secrets    DEBUG : secrets lus depuis IRIS_SECRET_<NAME>, coffre non ouvert",
                "  --in-memory-ca         DEBUG : CA éphémère, jamais écrit dans le coffre",
                "  --log-level <niveau>   debug | info | warning | error (défaut : config.json)",
                "  --version              affiche la version",
                "  --help                 affiche cette aide",
                ""
            });
        }

        /// <summary>Valeur de l'option courante : l'argument suivant, non vide, qui n'est pas lui-même une option.</summary>
        private static string ValueOf(string[] args, ref int i)
        {
            string option = args[i];
            if (i + 1 >= args.Length || args[i + 1].Length == 0 || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                throw new ArgumentsException("valeur manquante pour " + option);
            i++;
            return args[i];
        }
    }
}
```

- [ ] **Step 4: Ajouter la source à `test.bat`**

Remplacer la ligne `set IRISD_SOURCES=` par :

```bat
set IRISD_SOURCES="%SRC%\irisd\Arguments.cs"
```

- [ ] **Step 5: Lancer les tests**

```bash
cmd //c test.bat; echo "EXIT=$?"
```

Attendu : 11 lignes `OK`, `11 test(s) réussi(s), 0 échec(s)`, `EXIT=0`.

- [ ] **Step 6: Commit**

```bash
git add src/irisd/Arguments.cs tests/Tests.cs test.bat
git commit -m "feat(irisd): analyse stricte des arguments de la spec §7

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: `Program.cs`, `build.bat` et dossier portable

**Files:**
- Create: `src\irisd\Program.cs`
- Create: `build.bat`
- Modify: `CLAUDE.md` (section « Build, tests, rendu »)

**Interfaces:**
- Consumes: `Irisd.Arguments` (tâche 4), `IrisKit.IrisVersion` (tâche 1), `config\irisd.exe.config` (tâche 3), `vendor\KeePass-2.61.1\*` (tâche 2), `app.manifest` (tâche 1).
- Produces: `build\Iris\irisd.exe` et le dossier portable ; `Irisd.Program.Main(string[]) : int` avec les constantes `ExitOk = 0`, `ExitArguments = 4` que la phase 1 complétera (1, 2, 3).

- [ ] **Step 1: Écrire `src\irisd\Program.cs`**

```csharp
using System;
using System.Text;
using IrisKit;

namespace Irisd
{
    /// <summary>
    /// Point d'entrée de irisd. Phase 0 : aide, version et codes de sortie ; le daemon lui-même arrive en phase 1.
    /// Codes de sortie (spec §7) : 0 normal, 1 données ou config, 2 coffre, 3 port occupé, 4 argument invalide.
    /// </summary>
    public static class Program
    {
        public const int ExitOk = 0;
        public const int ExitArguments = 4;

        public static int Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;

            Arguments options;
            try
            {
                options = Arguments.Parse(args);
            }
            catch (ArgumentsException ex)
            {
                Console.Error.WriteLine("irisd : " + ex.Message);
                Console.Error.WriteLine();
                Console.Error.Write(Arguments.Usage());
                return ExitArguments;
            }

            if (options.ShowHelp)
            {
                Console.Write(Arguments.Usage());
                return ExitOk;
            }
            if (options.ShowVersion)
            {
                Console.WriteLine("irisd " + IrisVersion.Value);
                return ExitOk;
            }
            if (!options.Foreground)
            {
                // Sans --foreground le socle affiche l'aide et sort code 1 (le mode arrière-plan arrive avec le lot autostart).
                Console.Error.Write(Arguments.Usage());
                return 1;
            }

            Console.WriteLine("irisd " + IrisVersion.Value + " : socle en construction, le daemon arrive avec la phase 1.");
            return ExitOk;
        }
    }
}
```

- [ ] **Step 2: Écrire `build.bat`**

```bat
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
set IRISKIT_SOURCES="%SRC%\IrisKit\IrisVersion.cs"
set IRISD_SOURCES="%SRC%\irisd\Arguments.cs" "%SRC%\irisd\Program.cs"

"%CSC_PATH%" -nologo -codepage:65001 -target:exe -optimize+ -win32manifest:"%ROOT%app.manifest" -r:System.dll,System.Core.dll,System.Web.Extensions.dll,System.Security.dll -r:"%VENDOR%\KeePass.exe" -out:"%OUT%\irisd.exe" "%SRC%\AssemblyInfo.cs" %IRISKIT_SOURCES% %IRISD_SOURCES%
if %ERRORLEVEL% neq 0 (
    echo [ECHEC] Compilation de irisd.exe impossible.
    exit /b 1
)

rem --- Dossier portable ---------------------------------------------------
copy /y "%ROOT%config\irisd.exe.config" "%OUT%\irisd.exe.config" >nul
copy /y "%VENDOR%\KeePass.exe" "%OUT%\" >nul
copy /y "%VENDOR%\KeePass.exe.config" "%OUT%\" >nul
copy /y "%VENDOR%\KeePass.XmlSerializers.dll" "%OUT%\" >nul
copy /y "%VENDOR%\License.txt" "%OUT%\KeePass-License.txt" >nul

echo.
echo [SUCCES] Dossier portable assemble : %OUT%
exit /b 0
```

Puis :

```bash
sed -i 's/\r*$/\r/' build.bat
```

- [ ] **Step 3: Compiler et vérifier le contenu de `build\Iris\`**

```bash
cmd //c build.bat; echo "EXIT=$?"; ls build/Iris
```

Attendu : `[SUCCES]`, `EXIT=0`, et exactement : `KeePass-License.txt KeePass.XmlSerializers.dll KeePass.exe KeePass.exe.config irisd.exe irisd.exe.config`.

- [ ] **Step 4: Vérifier les codes de sortie de `irisd.exe`**

```bash
cd build/Iris
./irisd.exe --version; echo "EXIT=$?"
./irisd.exe --help | head -2; echo "EXIT=${PIPESTATUS[0]}"
./irisd.exe; echo "EXIT=$?"
./irisd.exe --foreground --verbose; echo "EXIT=$?"
./irisd.exe --data --foreground; echo "EXIT=$?"
./irisd.exe --foreground; echo "EXIT=$?"
cd ../..
```

Attendu, dans l'ordre : `irisd 0.1.0` / `EXIT=0` ; `Usage : irisd --foreground ...` / `EXIT=0` ; usage sur stderr / `EXIT=1` ; `irisd : option inconnue : --verbose` / `EXIT=4` ; `irisd : valeur manquante pour --data` / `EXIT=4` ; `irisd 0.1.0 : socle en construction...` / `EXIT=0`. Les accents (`défaut`, `éphémère`) sont lisibles.

- [ ] **Step 5: Vérifier la version de fichier de l'exécutable**

```powershell
(Get-Item build\Iris\irisd.exe).VersionInfo | Select-Object FileVersion, ProductVersion, FileDescription
```

Attendu : `FileVersion 0.1.0.0`, `ProductVersion 0.1.0.0`, `FileDescription irispc`.

- [ ] **Step 6: Vérifier le dépôt dans un chemin avec espace**

`git archive HEAD` ne contient pas encore `build.bat` ni `Program.cs` (non commités), d'où la copie manuelle :

```bash
T="$TEMP/irispc test"; rm -rf "$T"; mkdir -p "$T/src/irisd"
git archive HEAD | tar -x -C "$T"
cp build.bat "$T/" && cp src/irisd/Program.cs "$T/src/irisd/"
(cd "$T" && cmd //c build.bat && cmd //c test.bat); echo "EXIT=$?"
rm -rf "$T"
```

Attendu : `[SUCCES]` pour les deux scripts, `EXIT=0`.

- [ ] **Step 7: Mettre à jour `CLAUDE.md`, section « Build, tests, rendu »**

Remplacer la puce « Flags csc de référence » par :

```
- Flags csc de référence : `-nologo -codepage:65001 -optimize+ -win32icon:app.ico -win32manifest:app.manifest -r:System.dll,System.Core.dll,System.Web.Extensions.dll,System.Security.dll` (plus `System.Windows.Forms.dll,System.Drawing.dll` pour l'app). `-codepage:65001` est obligatoire : les sources sont en UTF-8 sans BOM et contiennent des accents. Depuis Git Bash, utiliser la forme `-flag` : `/flag` est réécrit en chemin. Jamais de package NuGet.
```

Dans la puce « Dossier portable `build\Iris\` », remplacer « leurs `.exe.config`, » par « leurs `.exe.config` (modèles dans `config\`), ».

- [ ] **Step 8: Vérifier l'état git**

```bash
git status --short
```

Attendu : `CLAUDE.md`, `build.bat`, `src/irisd/Program.cs` seulement ; pas de `build/`.

- [ ] **Step 9: Commit**

```bash
git add src/irisd/Program.cs build.bat CLAUDE.md
git commit -m "feat(irisd): point d'entrée minimal et build.bat du dossier portable

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: CI GitHub Actions verte

**Files:**
- Create: `.github\workflows\ci.yml`

**Interfaces:**
- Consumes: `test.bat` (tâches 3–4), `build.bat` (tâche 5).
- Produces: workflow `CI` sur `push` et `pull_request`, artefact `irispc-portable` = `build\Iris`.

- [ ] **Step 1: Écrire `.github\workflows\ci.yml`**

```yaml
name: CI

on:
  push:
  pull_request:

jobs:
  build-test:
    runs-on: windows-latest
    timeout-minutes: 15
    defaults:
      run:
        shell: cmd
    steps:
      - uses: actions/checkout@v4

      - name: Compilateur csc.exe natif
        run: dir "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

      - name: Tests (test.bat)
        run: call test.bat

      - name: Build (build.bat)
        run: call build.bat

      - name: Dossier portable
        uses: actions/upload-artifact@v4
        with:
          name: irispc-portable
          path: build/Iris
          if-no-files-found: error
```

- [ ] **Step 2: Vérifier la syntaxe YAML localement**

```bash
python -I -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('YAML_OK')" || echo "PyYAML absent : validation par GitHub à l'étape 4"
```

Attendu : `YAML_OK` (ou le message de repli).

- [ ] **Step 3: Commit et push de la branche**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: test.bat puis build.bat sur windows-latest, artefact du dossier portable

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
git push -u origin feat/phase-0-socle
```

- [ ] **Step 4: Attendre le run et vérifier qu'il est vert**

```bash
RUN=$(gh run list --branch feat/phase-0-socle --limit 1 --json databaseId --jq '.[0].databaseId'); echo "RUN=$RUN"
gh run watch --exit-status "$RUN"; echo "EXIT=$?"
```

Attendu : `completed success`, `EXIT=0`. Si le run échoue : `gh run view "$RUN" --log-failed`, corriger, commiter (`fix(ci): ...`), re-pousser, re-vérifier. Ne pas passer à la tâche 7 tant que le run n'est pas vert.

- [ ] **Step 5: Vérifier l'artefact**

```bash
gh run view "$RUN" --json artifacts --jq '.artifacts[].name'
```

Attendu : `irispc-portable`.

---

### Task 7: Pull request de la phase 0 (sans merge)

**Files:** aucun.

**Interfaces:**
- Consumes: la branche `feat/phase-0-socle` poussée et verte (tâche 6).
- Produces: une PR vers `main`, à merger en squash **après confirmation explicite de l'utilisateur** (hors plan).

- [ ] **Step 1: Relire l'ensemble du diff de la phase**

```bash
git log --oneline main..feat/phase-0-socle
git diff --stat main..feat/phase-0-socle
```

Attendu : 7 commits (spec + 6 tâches), aucun fichier généré (`build/`, `tests/*.exe`).

- [ ] **Step 2: Ouvrir la PR**

Écrire le corps dans le scratchpad (`pr-body.md`) avec le contenu ci-dessous, puis :

```bash
gh pr create --base main --head feat/phase-0-socle --title "Phase 0 : squelette, vendor KeePass, build.bat / test.bat, CI" --body-file "<scratchpad>/pr-body.md"
```

Corps :

```markdown
## Phase 0 — socle, squelette du dépôt

Spec : `docs/superpowers/specs/2026-10-17-socle-design.md` (§10, §11). Plan : `docs/superpowers/plans/2026-10-17-phase-0-squelette.md`.

- Squelette : `.gitignore`, `.gitattributes`, `README.md`, `app.manifest` (PerMonitorV2, asInvoker), version `0.1.0` portée par `AssemblyInfo.cs`, `app.manifest` et `IrisKit.IrisVersion`.
- `vendor\KeePass-2.61.1\` : `KeePass.exe` (KeePassLib), `.config`, `XmlSerializers.dll`, `License.txt`, README avec SHA-256.
- `tests\Check.cs` + `tests\Tests.cs` (harnais sans framework), `test.bat` ; `config\irisd.exe.config`.
- `src\irisd\Arguments.cs` : grammaire complète de la spec §7, analyse stricte, testée.
- `src\irisd\Program.cs` + `build.bat` : `irisd.exe` minimal, dossier portable `build\Iris\`.
- `.github\workflows\ci.yml` : `windows-latest`, `test.bat` puis `build.bat`, artefact.

## Smoke testing

- [ ] `test.bat` : 11 tests OK, code de sortie 0 ; une assertion volontairement fausse donne code 1
- [ ] `build.bat` : `build\Iris\` contient `irisd.exe`, `irisd.exe.config`, `KeePass.exe`, `KeePass.exe.config`, `KeePass.XmlSerializers.dll`, `KeePass-License.txt`
- [ ] `build\Iris\irisd.exe --version` affiche `irisd 0.1.0` (code 0)
- [ ] `irisd.exe --help` affiche l'usage en français avec accents lisibles (code 0)
- [ ] `irisd.exe` sans argument affiche l'usage sur stderr (code 1)
- [ ] `irisd.exe --foreground --verbose` → `option inconnue : --verbose` (code 4)
- [ ] `irisd.exe --data --foreground` → `valeur manquante pour --data` (code 4)
- [ ] Scripts lancés depuis un autre répertoire courant et depuis un chemin avec espace : OK
- [ ] CI verte sur la branche, artefact `irispc-portable` présent
- [ ] `git status` propre après `build.bat` + `test.bat` (rien de généré n'est suivi)
- [ ] Empreintes SHA-256 de `vendor\KeePass-2.61.1\` conformes au README

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

- [ ] **Step 3: Rendre compte à l'utilisateur**

Donner l'URL de la PR, l'état de la CI, et rappeler que le merge en squash attend sa confirmation explicite. Ne pas merger.

---

## Auto-revue du plan

- **Couverture de la spec (§10, §11 phase 0)** : arborescence (tâches 1–6), `build.bat` avec liste explicite et assemblage du dossier portable (5), `test.bat` compilant IrisKit + tests sans `Program.cs` et propageant le code (3), `ci.yml` windows-latest avec artefact (6), conventions C# 5 (contraintes globales), `vendor` avec README et SHA-256 (2), CLAUDE.md à jour (5), `.exe.config` du §3 (3). Grammaire et codes de sortie du §7 (4, 5) : les codes 1 (données), 2 et 3 appartiennent à la phase 1, qui possède le code qui les produit.
- **Placeholders** : aucun ; chaque étape porte son contenu.
- **Cohérence des types** : `Arguments.Parse` / `Usage` / `LogLevels`, `ArgumentsException`, `Check.True` / `Eq` / `Throws` / `Run` / `Summary`, `IrisVersion.Value`, `Program.ExitOk` / `ExitArguments` : mêmes noms dans les tâches 3, 4, 5 et dans la PR.
- **Review Focus** : 1 et 2 → tests `Arguments_MissingValue`, `Arguments_Duplicate` (tâche 4) ; 3 → `Arguments_UsageText` (tâche 4) et étape 5 de la tâche 3 ; 4 → tâche 3 étape 6 et CI ; 5 → tâche 5 étape 6.
