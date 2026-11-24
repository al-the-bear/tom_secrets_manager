# Tom Secrets Manager documentation

The documents that explain the Tom Secrets Manager as a whole: what it is,
how its parts fit together, how it keeps secrets safe, and how its main
flows run. The package READMEs, the protocol document and the user guides
explain each part in detail; these documents tie them together.

## The documents

| Document | What it explains |
| --- | --- |
| [Overview](overview.md) | What Tom Secrets Manager is, its components, and how it works, for a reader who has never seen the code |
| [Configuration reference](configuration.md) | Every file and folder, `bootstrap.yaml`, the device settings, `tsm.config`, the vaults' fields, the environment variables, the integrations' files, `relay.yaml`, the build's settings and the apps' preferences; a check holds it to the code |
| [Flows](flows.md) | Every flow step by step: first run, unlock, a client's request, pairing on every route, the approval link, sync, sharing, rotation, GitHub access, the browser, passkeys, the tools, import and export |
| [Security model](security.md) | The encryption layers, every key with its lifecycle, unlocking, trust between programs, machines and people, post-quantum protection, rotation, memory hygiene, the threat model, and how it is verified |
| [Architecture](architecture.md) | The repositories, the packages and their dependencies, the layers, the main types inside each component, the runtime views, and where a change plugs in |
| [Diagram style](diagram_style.md) | How the diagrams look, and why |

Each part's own documentation:

| Part | Document |
| --- | --- |
| The core library | [`tom_secrets_core` README](../tom_secrets_core/README.md) |
| The secrets service | [`tom_secrets_service` README](../tom_secrets_service/README.md) |
| Running and operating the service | [operator's guide](../tom_secrets_service/doc/user_guide.md) |
| Hosting a relay server | [relay operator's guide](https://github.com/al-the-bear/tom_app_secrets_manager/blob/main/tom_secrets_relay/doc/user_guide.md) |
| The protocol between the service and its clients | [protocol document](https://github.com/al-the-bear/tom_secrets_clients/blob/main/protocol/protocol.md) |
| The command line `tsm` | [`tsm` user guide](https://github.com/al-the-bear/tom_secrets_clients/blob/main/clients/dart/tsm/doc/tsm_user_guide.md) |
| The desktop app | [app user guide](https://github.com/al-the-bear/tom_app_secrets_manager/blob/main/tom_secrets_app/doc/user_guide.md) |
| The mobile app | [mobile user guide](https://github.com/al-the-bear/tom_app_secrets_manager/blob/main/tom_secrets_mobile/doc/user_guide.md) |
| The browser extension | [browser user guide](https://github.com/al-the-bear/tom_app_secrets_manager/blob/main/tom_secrets_browser/doc/user_guide.md) |
| Windows passkeys | [passkey plugin user guide](https://github.com/al-the-bear/tom_app_secrets_manager/blob/main/tom_secrets_passkey_plugin/doc/user_guide.md) |
| Checking, building and releasing | [build and release guide](https://github.com/al-the-bear/tom_app_secrets_manager/blob/main/tom_secrets_build/doc/user_guide.md) |

## How these documents are written

**Text.**

- Markdown lines are at most 80 characters long. Tables, code blocks,
  HTML comments and lines that hold only an image or a link are the
  exceptions.
- A document describes the product as it is now. It names no work item,
  no history and no internal design id.
- Examples use demo data only: no real secret, no personal path, no real
  host name.
- Facts come from the code, the protocol document and the design, and are
  checked against the code.

**Diagrams.** A diagram explains one aspect. It has as many nodes as that
aspect needs and no more: what the text explains, not every class or call.
A diagram that no longer reads at page width is split in two.

Each diagram appears in four parts, in this order:

1. a sentence that says what the diagram shows;
2. the diagram's SVG, as an image whose alt text is the diagram's title;
3. its Mermaid source, in an HTML comment right after the image;
4. the text that explains it.

The Mermaid source stays in the document, but GitHub does not render it:
the reader sees the SVG, which has the project's diagram style
([diagram_style.md](diagram_style.md)). To change a diagram, edit its
Mermaid source and export it again. Never edit the SVG or PNG by hand.

The comment starts with `<!-- diagram <n>-<slug>`, where `<n>` numbers the
diagrams of the document and `<slug>` names this one. GitHub ends an HTML
comment at the first line that holds `-->`, so the source writes every `>`
as `&gt;` (`a --&gt; b`); the tools read it back as `>`, and the check
refuses a source that holds `-->`. The export writes
`images/diagrams/<document>/<n>-<slug>.svg` and `.png` beside the document.
The PNG is for places that show no SVG, such as an article on Medium.

This diagram shows how a document's diagrams become images and how the
check keeps them current.

![From Mermaid source to the published diagram](images/diagrams/README/1-docs-tooling.svg)

<!-- diagram 1-docs-tooling
```mermaid
flowchart LR
  subgraph doc["A document"]
    src["Mermaid source<br/&gt;in an HTML comment"]:::file
    img["The image"]:::file
  end
  export("render_diagrams.mjs"):::program
  check("check_docs.mjs<br/&gt;ci.sh :docs"):::program
  svg["SVG in the<br/&gt;website style"]:::file
  png["PNG for Medium"]:::file
  src --&gt; export
  export --&gt; svg
  export --&gt; png
  img -- shows --&gt; svg
  src --&gt; check
  svg --&gt; check
  class doc zoneDevice
```
-->

`render_diagrams.mjs` reads each diagram's source, renders it with
Mermaid and writes the SVG and the PNG. Each SVG carries a hash of its
source. `check_docs.mjs` renders every source again and fails when one does
not render. It also fails when an SVG is missing or older than its source,
when a relative link leads nowhere, or when a line is too long.

**One look for the same thing.** Every diagram uses the same classes,
which the export defines for every flowchart. A node names its class with
`:::<class>`, a subgraph with `class <id> <class>`:

| Class | Shape | For |
| --- | --- | --- |
| `program` | rounded box, navy | the product's programs: the service, the apps, `tsm`, the browser host |
| `library` | box, teal | a package or library inside a program |
| `client` | box, light blue | a program that asks for secrets |
| `person` | stadium `([ ])`, light blue | a person: the user, a member |
| `file` | box, amber | a file: a configuration, a share, an export |
| `vault` | cylinder `[( )]`, green | a vault, a store of secrets |
| `key` | hexagon `{{ }}`, magenta | a key, a password, a token |
| `external` | box, white | a service outside the product: GitHub, a relay |
| `zoneDevice` | subgraph, white | a trusted machine |
| `zoneSandbox` | subgraph, amber | a sandbox: a browser, an app extension |
| `zoneRemote` | subgraph, sand | a remote place: GitHub, the internet |

A solid arrow carries data. A dashed arrow (`-.->`) is an authorisation or
the way a key is used; the export draws it in magenta.

## Checking and exporting

The tools are in the `tom_app_secrets_manager` repository, in
`tom_secrets_build` (Node.js 20 or later; `npm ci` there first). From
`tom_secrets_build`, with this repository cloned beside it:

```text
node tool/render_diagrams.mjs ../../tom_secrets_manager/doc
node tool/check_docs.mjs ../../tom_secrets_manager/doc
```

`ci.sh :docs` runs the check over this folder and the user guides.
`render_diagrams.mjs --force` exports every diagram again, and `--hash`
prints each source's hash.

A diagram that leads a document can be drawn by hand in the website style
when the export falls short. Its comment then reads
`<!-- diagram <n>-<slug> hand-drawn`, and the export writes only its PNG.
The drawing's `data-tsm-source` attribute holds its source's hash (from
`--hash`), so the check still notices a changed source.

## The overview as an article

The overview is written to become an article on Medium: it tells one
story, each section reads on its own, and it names no repository internals
outside its closing links. The article is generated from it:
[`article/overview.medium.md`](article/overview.medium.md), with the
diagrams' PNGs in `article/images/`. From `tom_secrets_build`:

```text
node tool/render_diagrams.mjs ../../tom_secrets_manager/doc
node tool/export_article.mjs ../../tom_secrets_manager/doc
```

The export differs from the overview in four ways:

- each diagram's SVG image is replaced by its PNG, addressed on
  `raw.githubusercontent.com` (Medium fetches images by URL), and the
  diagram's HTML comment is left out;
- each relative link becomes an absolute GitHub address in the
  `tom_secrets_manager` repository, a link to a heading of the overview the
  overview on GitHub;
- each paragraph and list item is on one line, as Medium's editor takes
  pasted text;
- a comment on the first line says the file is generated.

The text in italics under the title is the article's subtitle. Never edit
the article: edit the overview and export again. `ci.sh :docs` fails while
the article is older than the overview (`export_article.mjs --check`); the
documentation check leaves the `article/` folder out, its lines being
Medium's.

## Screenshots

The guides' screenshots and transcripts are made from demo data, never from
real secrets, by one command per kind. Each writes its files where the guide
that shows them lives, as `<screen>-<state>-<theme>.png` (`light`, `dark`).

| Kind | Command, run in | Writes |
| --- | --- | --- |
| desktop app | `flutter test --tags screenshots --update-goldens test/screenshots` in `tom_secrets_ui` | `tom_secrets_app/doc/images/` |
| phone, tablet | the same in `tom_secrets_mobile` | `tom_secrets_mobile/doc/images/` |
| browser extension | `npm run build && npm run screenshots` in `tom_secrets_browser/extension` | `tom_secrets_browser/doc/images/` |
| `tsm` | `TSM_UPDATE_TRANSCRIPTS=1 dart test test/transcripts_test.dart` in `tsm` | the guide's transcript blocks |
| the service | `TSM_UPDATE_TRANSCRIPTS=1 dart test test/guide_transcripts_test.dart` in `tom_secrets_service` | the operator's guide's transcript blocks |
| the relay | the same in `tom_secrets_relay` | the relay guide's transcript blocks |

- **The Flutter screens** are pumped over the tests' fake service and demo
  vaults (the phone's over a fake GitHub), at 1440×900 for the desktop,
  390×844 for a phone and 1024×1366 for a tablet, in both themes, with the
  real fonts: Roboto and the Material icons from the Flutter SDK, and a
  monospace font of the system (`tom_secrets_ui`'s `screenshots.dart`).
  The tests are tagged `screenshots` and run only with `--update-goldens`;
  `testkit :test`, `flutter test` and `ci.sh :test` skip them, so no run
  compares them.
- **The extension** is loaded into headless Chromium (Playwright; once
  `npx playwright install chromium`) with the tests' fake host answering
  demo logins, on a demo login page served on 127.0.0.1: the in-page list,
  the save bar and the popup, in the light theme.
- **The `tsm` transcripts** are sessions against a demo installation. In the
  guide, a block marked `<!-- transcript <name> -->` holds a session, and
  `test/transcripts_test.dart` names its commands. The test fails when the
  guide no longer shows what `tsm` prints; the command above writes it
  again.

The operating systems' own dialogs are not made this way: Windows' passkey
dialog, macOS's AutoFill and passkey sheets, Safari's extension settings,
Touch ID and Windows Hello. The user captures them during the live checks,
or the guide describes them without an image.
