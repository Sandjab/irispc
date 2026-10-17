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
