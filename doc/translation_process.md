Translations
============

BitcoinAll Core supports multiple localisations. New phrases and languages are added via pull requests in this repository.

### Helping to translate

Contributions are welcome through GitHub:

- Open a pull request with updated files under `src/qt/locale/`
- Or open an [issue](https://github.com/gonzalolinaresamezcua/BitcoinAll/issues) if you need guidance

There is no Transifex project, mailing list, or external translation site for BitcoinAll.

### Writing code with translations

We use automated scripts to extract translations in both Qt and non-Qt source files. It is rarely necessary to manually edit the files in `src/qt/locale/`. The translation source files must adhere to the following format:
`bitcoin_xx_YY.ts or bitcoin_xx.ts`

`src/qt/locale/bitcoin_en.ts` is treated in a special way. It is used as the source for all other translations. Whenever a string in the source code is changed, this file must be updated to reflect those changes. A custom script is used to extract strings from the non-Qt parts. This script makes use of `gettext`, so make sure that utility is installed (ie, `apt-get install gettext` on Ubuntu/Debian). Once this has been updated, `lupdate` (included in the Qt SDK) is used to update `bitcoin_en.ts`.

To automatically regenerate the `bitcoin_en.ts` file, run the following commands:
```sh
cmake --preset dev-mode -DWITH_USDT=OFF -DENABLE_IPC=OFF
cmake --build build_dev_mode --target translate
```

**Example Qt translation**
```cpp
QToolBar *toolbar = addToolBar(tr("Tabs toolbar"));
```

### Creating a pull-request

For general PRs, you shouldn't include updates to translation source files unless your PR changes user-visible strings. Translation sync can be done in separate PRs before releases.

To create the pull-request after regenerating strings:
```
git add src/qt/bitcoinstrings.cpp src/qt/locale/bitcoin_en.ts
git commit
```

See also [Translation Strings Policy](translation_strings_policy.md).

Copyright (c) 2025-2026 Bitcoin All Developers. See [COPYING](../COPYING).
