# tidyscan

Ordner analysieren und sicher aufräumen. Ein Binary für Windows, macOS und Linux, mit grafischer Oberfläche und Kommandozeile.

**Nichts wird gelöscht.** Alles, was tidyscan aufräumt, wandert in einen Quarantäne-Ordner und lässt sich mit einem Klick oder Befehl zurückholen.

## Funktionen

- **Strukturanalyse**: Ordnerbaum mit Größen, Dateianzahl, Anteil am Gesamtvolumen, Aufteilung nach Kategorie (Bilder, Videos, Dokumente, Installer, …), Altersverteilung und größte Dateien.
- **Alte Dateien**: alles, was seit N Tagen unverändert ist. Zugriffszeiten werden auf Zuverlässigkeit geprüft, weil Windows NTFS und Linux `relatime` sie meist nicht aktualisieren.
- **Duplikate**: byte-identische Dateien über Größe, Präfix-Hash und vollständigen BLAKE3-Hash, parallel auf allen Kernen.
- **Leere Ordner und 0-Byte-Dateien**, rekursiv erkannt.
- **Regeln** in TOML: nach Endung, Glob, Kategorie, Alter und Größe filtern und in Quarantäne oder einen Zielordner (mit `{year}`/`{month}`-Platzhaltern) verschieben.
- **Plan mit Vorschau, Quarantäne und Undo**: Häkchen in der GUI oder Regel-Treffer landen in einem Plan. Beim Ausführen wird jede Bewegung in `undo.json` protokolliert.

## Installation

Voraussetzung ist eine Rust-Toolchain (https://rustup.rs). Unter Linux werden zusätzlich die GTK-Entwicklungspakete für den Dateidialog benötigt:

```bash
sudo apt install libgtk-3-dev libxkbcommon-dev libssl-dev
```

Bauen:

```bash
cargo build --release
```

Das Binary liegt danach unter `target/release/tidyscan` (Windows: `tidyscan.exe`).

## GUI

```bash
tidyscan
tidyscan gui ~/Downloads
```

Links Ordner wählen und scannen. Die Tabs **Übersicht**, **Alte Dateien**, **Duplikate** und **Leere Ordner** zeigen die Ergebnisse. Häkchen setzen füllt den Plan im Tab **Aufräumen**. Dort lassen sich außerdem Regeldateien anwenden, der Plan ausführen und frühere Sitzungen rückgängig machen.

## Automatik

Der Tab **Automatik** (CLI: `auto` und `organize`) berechnet mit einem Klick einen Vorschlag und führt ihn erst nach einem zweiten Klick aus. Jeder Eintrag ist entweder **sicher**, **unsicher** oder **geschützt**:

- **Sicher** wird ohne Nachfrage erledigt: Müll- und Temporärdateien (Thumbs.db, .DS_Store, *.tmp, Office-Sperrdateien älter als ein Tag, abgebrochene Downloads älter als eine Woche), 0-Byte-Dateien, exakte Duplikate außerhalb von Projekten (eine Kopie bleibt, bevorzugt die außerhalb von Downloads), leere Ordner älter als eine Woche, alte Installer in Downloads (ab 90 Tagen) und Archive, neben denen bereits der entpackte Ordner liegt.
- **Unsicher** wird mit Begründung gelistet, du entscheidest per Häkchen. **Nachprüfen** liefert zusätzliche Hinweise: ob eine Datei gerade geöffnet ist, ob sie sich seit dem Scan verändert hat, ob die erhaltene Duplikat-Kopie wirklich noch byte-identisch ist, ob ein entpackter Ordner existiert. Was die Prüfung besteht, rutscht in die sichere Liste.
- **Geschützt** wird nie angefasst: Projektordner (Git, Cargo, npm, Python, Unity, …), `node_modules`, `.git`, Spiele-Bibliotheken, Programm- und Systemordner, AppData.

Die **Sortier-Automatik** räumt lose Dateien nach Kategorie in `Bilder/`, `Videos/`, `Audio/`, `Dokumente/`, `Archive/`, `Installer/`, `Disk-Images/` (bestehende Ordner wie `Pictures` oder `Documents` werden als Ziel erkannt, optional mit Jahres-Unterordner). Zusammenhängende Unterordner (mindestens 80 % eine Kategorie) wandern als Ganzes unter ihren Kategorie-Ordner, gemischte Unterordner werden nur als Vorschlag zum Verteilen gezeigt. Begleitdateien wie `foto.jpg` + `foto.xmp` bleiben zusammen, Code, Verknüpfungen und Unbekanntes werden nicht verschoben. Eine Vorher/Nachher-Ansicht zeigt die Struktur, bevor etwas passiert.

Vor jedem Verschieben prüft tidyscan erneut, ob die Datei seit dem Scan unverändert ist und ob die erhaltene Duplikat-Kopie noch existiert. Alles landet wie gewohnt in der Quarantäne bzw. im Zielordner und ist über das Journal rückgängig machbar.

## CLI

```bash
tidyscan auto <pfad> [--apply] [--include-unsure] [--no-dupes] [--json]
tidyscan organize <pfad> [--by-year] [--apply] [--include-unsure] [--json]
tidyscan scan <pfad> [--top 20] [--json]
tidyscan old <pfad> --days 365 [--use-atime]
tidyscan dupes <pfad> [--min-size 1M]
tidyscan empty <pfad>
tidyscan clean <pfad> --rules rules.toml          # Vorschau
tidyscan clean <pfad> --rules rules.toml --apply  # wirklich verschieben
tidyscan undo --root <pfad>                       # neueste Sitzung zurücknehmen
tidyscan undo <pfad>/.tidyscan-quarantine/<zeitstempel>/undo.json
tidyscan example-rules > rules.toml
```

Alle Scan-Befehle kennen `--skip-hidden`, `--exclude <GLOB>` (mehrfach) und `--max-depth N`.

## Regeln

```toml
[[rule]]
name = "Alte Installer in Quarantäne"
ext = ["exe", "msi", "dmg", "pkg", "deb"]
older_than_days = 90
action = "quarantine"

[[rule]]
name = "Screenshots nach Jahr archivieren"
glob = "**/Screenshot*"
older_than_days = 30
action = "move"
move_to = "Archiv/Screenshots/{year}"
```

Bedingungen: `ext`, `glob` (relativ zum Scan-Ordner, immer mit `/`), `category` (bilder, videos, audio, dokumente, archive, code, installer, disk-images, sonstiges), `older_than_days`, `min_size`, `max_size` (`500`, `10K`, `1.5M`, `2G`). Die erste passende Regel gewinnt. Ein vollständiges Beispiel liegt in [rules.example.toml](rules.example.toml).

## Quarantäne

Verschobene Dateien und Ordner liegen unter `<Scan-Ordner>/.tidyscan-quarantine/<Zeitstempel>/` mit ihrer ursprünglichen relativen Struktur. Daneben liegt `undo.json`. Ein Undo stellt alles wieder her und überschreibt dabei nie etwas, was inzwischen am Originalpfad liegt.

Ganze Ordner samt Inhalt lassen sich in der Übersicht über "Ganzen Ordner in Quarantäne (Plan)" aufnehmen; sie werden als Einheit verschoben und als Einheit wiederhergestellt.

Der Tab **Quarantäne** listet alle Sitzungen mit Größe, lässt einzelne Einträge oder ganze Sitzungen wiederherstellen und ist die einzige Stelle, an der tidyscan Daten **endgültig löscht**, immer nach Rückfrage und nur innerhalb des Quarantäne-Ordners. Auf der Kommandozeile:

```bash
tidyscan quarantine <pfad>                 # Sitzungen auflisten
tidyscan purge --root <pfad> [--all]       # zeigt, was gelöscht würde
tidyscan purge --root <pfad> --all --yes   # löscht endgültig
```

## Grenzen und Hinweise

- Symlinks, Junctions und Cloud-Platzhalter (OneDrive, iCloud "nur online") werden übersprungen und nicht mitgezählt.
- `$RECYCLE.BIN`, `System Volume Information`, `.Trashes`, `.Spotlight-V100` und die Quarantäne selbst werden nie gescannt.
- Zugriffszeiten sind auf den meisten Systemen unzuverlässig. tidyscan prüft das per Stichprobe und fällt auf das Änderungsdatum zurück.
- Inhaltliches Gruppieren ("diese Dateien gehören zusammen") ist noch nicht enthalten.

## Entwicklung

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
```

Die Kernlogik liegt in `src/` als Bibliothek (`scan`, `analysis`, `age`, `dupes`, `rules`, `actions`), `cli.rs` und `ui/` sind dünne Schichten darüber.

## Lizenz

MIT
