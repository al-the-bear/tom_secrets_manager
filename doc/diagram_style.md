# Diagram style

The diagrams of these documents look like the diagrams on
enterprise-flutter.dev, the project's homepage. Those diagrams are drawn
by hand as SVG. This document writes their style down, so that the
exported diagrams follow it and a diagram drawn by hand can match them.

## The samples

The style is taken from the website's diagrams: the anatomy of a Tom
application, the development environment, from DocSpecs to CodeSpecs, the
Tom architecture, and the D4rt interpreter. They share one palette, one
font and one set of shapes, on a light background.

## The palette

| Colour | Hex | Used for |
| --- | --- | --- |
| Navy | `#0E2841` | text, titles, the main boxes (white text on them) |
| Slate | `#41576C` | lines, arrows, captions |
| Panel | `#F4F8FB` | the background panel behind the whole diagram |
| White | `#FFFFFF` | boxes outside the main group, group backgrounds |
| Border | `#D7E1EA` | the border of white boxes |
| Group border | `#C9D8E4` | the border of a group (a trust zone) |
| Teal | `#156082` | inner boxes: packages, layers |
| Blue | `#0F7FB0` | a highlighted path or layer |
| Deep blue | `#1B4B70` | the lowest layer |
| Magenta | `#A02B93` | authorisation paths (dashed lines) |
| Magenta text | `#7A2186` | text on magenta paths and key boxes |
| Green | `#1F7A2E` on `#E7F6EC`, border `#9ED9AE` | databases and vaults |
| Amber | `#FFF7ED`, border `#F3D6BE` | files, sandboxes |
| Lilac | `#F3ECF7`, border `#C9B6D8` | keys |
| Sky | `#EAF4FA`, border `#BFD9EA` | clients, people |
| Sand | `#F1EFE8`, border `#D3D1C7` | remote places |
| Pale blue | `#B9CCDC` | captions on navy boxes |

## Type

The font is Inter, with the system's sans-serif after it:
`Inter, -apple-system, "Segoe UI", Roboto, sans-serif`. Names of code
(packages, programs) may use JetBrains Mono. The text classes:

| Class | Size and weight | Colour | For |
| --- | --- | --- | --- |
| title | 14–15 px, 700, upper case, letter spacing .04 em | navy | a group's title |
| heading | 14–15 px, 700 | navy, or white on navy | a box's name |
| label | 12.5–13 px, 600 | navy, or white on navy | a smaller box's name |
| caption | 11–11.5 px, 400 | slate, or pale blue on navy | a line under a name, an edge's label |
| code | 11–12.5 px, JetBrains Mono | white on teal | a package name in a box |
| muted | 12–12.5 px, 600, italic | `#7B8D9C` | a remark |

## Shapes and lines

- **The panel.** The whole diagram sits on a panel of `#F4F8FB` with
  corners of radius 22.
- **Groups** are white with a 1.6 px border of `#C9D8E4` and corners of
  radius 18. Their title stands at the top.
- **Boxes** have corners of radius 9 to 14. Main boxes are navy with white
  text; boxes outside the main group are white with a `#D7E1EA` border.
- **Databases and vaults** are green cylinders.
- **Lines** are 1.5 to 1.8 px. A plain line is slate; a highlighted path is
  blue; an authorisation path is magenta and dashed (`6 5`).
- **Arrowheads** are small filled triangles (7 by 7) in the line's colour.

## Accessibility

Every SVG has `role="img"` and an `aria-label` with its title. Its first
children are a `<title>` (the diagram's title) and a `<desc>` (what it
shows, in a sentence or two).

## How the export applies the style

`render_diagrams.mjs` renders Mermaid's `base` theme with this palette and
font, Mermaid's classic look (no drop shadows), and the class set of the
[documentation README](README.md#how-these-documents-are-written). It then
adds the panel, the font stack, `role`, `aria-label`, `<title>` (the
image's alt text) and `<desc>` (the sentence before the image).

Where Mermaid cannot follow the samples:

- a group's title is centred, where the samples put it at the left;
- Mermaid routes the lines itself, with rounded bends, where the samples
  place each line by hand;
- an arrowhead keeps the slate colour on a magenta dashed line.

A diagram that leads a document and needs the samples' finish is drawn by
hand in this style instead, as the website's are (see the README's
"Checking and exporting").
