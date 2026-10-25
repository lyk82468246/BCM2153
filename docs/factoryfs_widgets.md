# FactoryFs widget configuration and entry paths

The default-widget list names three ZIP-based packages already present under
`SystemFS/MediaSet/Widget`. Their manifests, entry HTML and selected JavaScript
establish a reproducible configuration-to-script chain. The native installer,
mount aliases and implementation of the JavaScript `widget` object remain
unknown; this is static artifact analysis, not a successful device launch.

## Source identity and package boundaries

FactoryFs SHA-256:
`c33b5d69e1376434cefa444e51afd7d5889cfbe6335521678e91433dd2238726`,
37,836,800 bytes. Sleuth Kit 4.12.1 `fls -r -p` and `icat` supplied the selected
allocated files. The script uses Python 3.14.4 and the standard library only.

`SystemFS/User/Widget/WidgetDefault.ini`, inode `1177353`, has 216 bytes. It
declares `WidgetCount=3`, and in order names Baidu, Sina, then Qzone, each with
`Activation=1`. These are stored configuration values; their consumer and the
meaning of activation on a running device have not been established.

| Package basename | Inode | ZIP bytes | Members, including directories | Expanded file bytes |
| --- | ---: | ---: | ---: | ---: |
| `Baidu_BKCN_cn_T_0_02.wgt` | 879879 | 19,837 | 12 | 22,796 |
| `Sina_BKCN_cn_T_0_05.wgt` | 879883 | 85,192 | 53 | 122,484 |
| `qzone.wgt` | 879880 | 107,349 | 93 | 178,373 |

Package SHA-256, in the same order:

- Baidu: `27a3e25b21e24bf166ceac0a8759f84d97c2499d7bcde5fc40eaa057aacf5ed7`.
- Sina: `1da8c9adfc32b5849da45916dc87cccd073168357d79a3906ce545ed38934cce`.
- Qzone: `7f31bfdd50c29379b978033b6927e25aace9b64805eb57bee62ffa900b9d2ebc`.

All files in these three archives passed ZIP CRC and declared-size checks.
All three root manifests use `http://www.w3.org/ns/widgets`, declare network
access, and select `index.html`. All entry-HTML `src`/`href` references checked
by the probe resolve to members. CSS URLs, inline style URLs and dynamically
constructed paths are outside that check.

## Entry and host dependencies

| Package | Manifest ID/version | Declared size | Entry body event | Static script path |
| --- | --- | --- | --- | --- |
| Baidu | `SOFBKCNLCNBAIDU______001` / `0.02` | 200×90 | `initIdle()` | Four script references; `js/user.js` clears the input, shows idle and requests 188×86 |
| Sina | `SOFBKCNLCNSINA_______001` / `0.05` | 200×90 | `pageInit()` | Seven script references; initializes navigation, mode handling and idle page |
| Qzone | `USRBRCNLZHQZONE` / `00.01` | 192×164 | `pageLoaded()` | Eight script references; initialization/preload wrappers then `widgetCreate()` |

Baidu's `js/user.js:1` calls `idleLoad`, which sets the idle layer to `block`
and calls `resizeWindow(188,86)` at line 9. The wrapper in `js/common.js:10`
attempts `widget.window.resizeWindow(width,height)` and catches exceptions.
The search action uses `widget.openURL`, falling back to location navigation.
No search request was sent.

Sina's `js/user.js:28` initializes navigation and calls `mode.init()` before
going to idle. `js/mode.js:14` conditionally registers `widgetmodechange`;
line 46 queries `widget.window.getCurrentDirection()`. The source maps
`horizontal` to its width layout and uses height layout as the exception fallback.
This establishes an application-facing direction/event dependency, not its
native event delivery implementation.

Qzone's `js/indexhandler.js:24` calls initialization, preload and `widgetCreate`.
That function reads preferences through `WidgetAPI` and selects a login window.
The wrapper in `js/widgetapi.js` supplies window sizing, direction and preference
access. The ASCII prefix of `js/window.js:4` registers `widgetendkey`, while its
resize handler selects 320×240 or 240×320. That file has an invalid UTF-8 byte
at offset 8386; its encoding was not guessed or changed. These prefix
observations come from ordinary byte inspection, not a successful REA parse
of the complete file. No account interaction or network access was performed.

The three manifest IDs are package identifiers. They do not explain the IMRC
global ID space or RBM local selectors, and these files do not prove that
ShpApp implements the entire native menu.

## Evidence and limits

REA parsed inert extracted source trees with `analyze_javascript_application`:

- Baidu parent Evidence: `ev_0c9a4c301edb8f5ec36cf33a0847338ac49395ea3f91a9fed5f5bd8a2e6524f2`.
  Four JavaScript files parsed, no parse failures; application coverage partial,
  semantic coverage unknown, with 139 semantic unknowns.
- Sina parent Evidence: `ev_6edae296314fb3034ddcc01fc521ffe87c512cbd6649187f3144e9b6a630523f`.
  Selected `index.html`, `js/common.js`, `js/config.js`, `js/mode.js`,
  `js/navi.js`, `js/user.js`; five JS files parsed. Two relevant sources and
  the inline HTML script remain outside analysis. Application/semantic coverage
  partial, with 3/934 unknowns respectively.
- Qzone parent Evidence: `ev_4e6aaee3728f0c01ace73de8852e820fa8f2f7968518f0c35df588fe62f0dd2d`.
  Selected `index.html`, `js/widgetapi.js`, `js/indexhandler.js`, `js/window.js`;
  two JS files parsed and one invalid-UTF-8 file recorded. Five other relevant
  sources remain unselected. Coverage partial, with 6/586 application/semantic
  unknowns. A zero parse-failure count does not mean the invalid file parsed.

The local complete bundle `out/factoryfs_widgets/widgets.rea.evidence.json`
retains these records and limitations. Config/INI parsing, ZIP CRC validation
and exact source-line reads are ordinary tools, separate from REA graph evidence.
Static calls do not establish execution, host binding or supported standards.

## Reproduce

Keep all extracted packages local:

```sh
mkdir -p out/factoryfs_widgets
icat /home/joe/thing/FactoryFs_B5310_China.ffs 879879 > out/factoryfs_widgets/Baidu_BKCN_cn_T_0_02.wgt
icat /home/joe/thing/FactoryFs_B5310_China.ffs 879883 > out/factoryfs_widgets/Sina_BKCN_cn_T_0_05.wgt
icat /home/joe/thing/FactoryFs_B5310_China.ffs 879880 > out/factoryfs_widgets/qzone.wgt
icat /home/joe/thing/FactoryFs_B5310_China.ffs 1177353 > out/factoryfs_widgets/WidgetDefault.ini
python3 tools/widget_package_probe.py out/factoryfs_widgets/Baidu_BKCN_cn_T_0_02.wgt \
  --out out/factoryfs_widgets/baidu.package.json
```

Run the same probe with the Sina/Qzone inputs and fresh output paths. It reads
at most 8 MiB of packed input, admits at most 512 members, 1 MiB per member and
16 MiB expanded total. It rejects duplicate/noncanonical members, corrupt CRCs,
unsupported XML declarations and missing/nonlocal entry paths. It extracts no
files, executes no handlers and refuses to overwrite reports. Tests cover these
boundaries and base-element uncertainty. Package scripts and full manifests
remain ignored under `out/`.

The [native binding follow-up](shpapp_widget_bindings.md) links window/event API
names to native callback records and follows three adapters. The configuration
consumer, final method targets and event delivery remain unresolved. Widget
lifecycle remains separate from browser drawing and native-menu ownership.
The two bookmark ZIP templates are a separate lead:
their HTML references files absent from the stored templates, so an installation
or generation step would be needed before treating them as complete widgets.
