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
