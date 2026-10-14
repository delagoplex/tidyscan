# tidyscan

Ordner analysieren und sicher aufräumen. Ein Binary für Windows, macOS und Linux, mit grafischer Oberfläche und Kommandozeile.

**Nichts wird gelöscht.** Alles, was tidyscan aufräumt, wandert in einen Quarantäne-Ordner und lässt sich mit einem Klick oder Befehl zurückholen.

## Funktionen

- **Strukturanalyse**: Baumtabelle wie in TreeSize mit sortierbaren Spalten (Größe, Anteil-Balken, Dateien, Ordner, letzte Änderung), darunter eine Treemap mit Zoom (Doppelklick) und wählbarer Verschachtelungstiefe, daneben Details zum gewählten Ordner: Kategorien, Altersverteilung, größte Dateien.
- **Alte Dateien**: alles, was seit N Tagen unverändert ist. Zugriffszeiten werden auf Zuverlässigkeit geprüft, weil Windows NTFS und Linux `relatime` sie meist nicht aktualisieren.
- **Duplikate**: byte-identische Dateien über Größe, Präfix-Hash und vollständigen BLAKE3-Hash, parallel auf allen Kernen.
- **Leere Ordner und 0-Byte-Dateien**, rekursiv erkannt. Leer heißt: der Scan hat alles darunter gesehen und keine Datei gefunden. Ordner mit übersprungenen Inhalten (versteckt, ausgeschlossen, Verknüpfungen, Cloud-Platzhalter), nicht lesbare Ordner und abgebrochene Scans zählen nie als leer.
- **Regeln** in TOML: nach Endung, Glob, Kategorie, Alter und Größe filtern und in Quarantäne oder einen Zielordner (mit `{year}`/`{month}`-Platzhaltern) verschieben.
- **Plan mit Vorschau, Quarantäne und Undo**: Häkchen in der GUI oder Regel-Treffer landen in einem Plan. Beim Ausführen wird jede Bewegung in `undo.json` protokolliert. Jeder Eintrag wird unmittelbar vor dem Verschieben noch einmal geprüft: Dateien, die sich seit dem Scan verändert haben, und "leere" Ordner, die inzwischen etwas enthalten, bleiben liegen und werden als übersprungen gemeldet.

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

Links Ordner wählen und scannen. Die Tabs **Übersicht**, **Alte Dateien**, **Duplikate** und **Leere Ordner** zeigen die Ergebnisse. Häkchen setzen füllt den Plan im Tab **Aufräumen**. Dort lassen sich außerdem Regeldateien anwenden und der Plan ausführen. Frühere Sitzungen macht der Tab **Quarantäne** rückgängig.

Plan und Quarantäne gehören immer zu dem Ordner, der gescannt wurde (links unter "Gescannt" angezeigt), auch wenn im Ordnerfeld inzwischen etwas anderes steht. Ausführen, Wiederherstellen und Löschen laufen im Hintergrund mit Fortschrittsanzeige.

## Automatik

Der Tab **Automatik** (CLI: `auto` und `organize`) berechnet mit einem Klick einen Vorschlag und führt ihn erst nach einem zweiten Klick aus. Jeder Eintrag ist entweder **sicher**, **unsicher** oder **geschützt**:

- **Sicher** wird ohne Nachfrage erledigt: Müll- und Temporärdateien (Thumbs.db, .DS_Store, *.tmp, Office-Sperrdateien älter als ein Tag, abgebrochene Downloads älter als eine Woche), 0-Byte-Dateien, exakte Duplikate außerhalb von Projekten (eine Kopie bleibt, bevorzugt die außerhalb von Downloads), leere Ordner älter als eine Woche, alte Installer, die lose im Downloads-Ordner liegen (ab 90 Tagen), und Archive, neben denen bereits der entpackte Ordner liegt.
- **Unsicher** wird mit Begründung gelistet, du entscheidest per Häkchen. **Nachprüfen** hängt vom Grund der Unsicherheit ab:
  - *kürzlich geändert*: wird sicher, wenn die Datei seit dem Scan unverändert und von keinem Programm geöffnet ist. Dieser Test existiert nur unter Windows, unter Linux und macOS bleibt der Eintrag unsicher.
  - *prüfbar*: Duplikate werden erneut Byte für Byte verglichen, bei Archiven wird der entpackte Ordner gesucht, leere Ordner werden auf der Platte nachgesehen.
  - *Projektzugehörigkeit* und *Fragen der Absicht* (portables Programm oder Installer? gehören die Dateien eines gemischten Ordners zusammen?) entscheidet keine Prüfung, die bleiben bei dir.
  - Findet die Prüfung einen Grund, die Datei jetzt nicht anzufassen (geöffnet, seit dem Scan verändert), wird der Eintrag **gesperrt** und lässt sich nicht mehr auswählen.
- **Geschützt** wird nie angefasst: Projektordner (Git, Cargo, npm, Python, Unity, …), `node_modules`, `.git`, Spiele-Bibliotheken sowie die System-, Programm- und Anwendungsdaten-Ordner dieses Rechners (Windows: `%SystemRoot%`, `Program Files`, `ProgramData`, `AppData`; macOS: `/System`, `/Library`, `~/Library`; Linux: `/usr`, `/etc`, `~/.config`, `~/.local/share`, …). Der Temp-Ordner ist die einzige Ausnahme. Der Schutz gilt für jeden Ordner im Scan: wer den Benutzerordner scannt, öffnet damit nicht `AppData`. Liegt der gescannte Ordner selbst in einem Projekt, das weiter oben beginnt, zählt er als Projekt.

Ein Ordner gilt als Projekt, wenn er eine Projektdatei (`Cargo.toml`, `package.json`, `pyproject.toml`, `*.sln`, …) oder ein `.git`/`.hg`/`.svn` enthält. Schwache Hinweise wie `.gitignore`, `Makefile`, `requirements.txt` oder `.idea` zählen erst zu zweit.

Die **Sortier-Automatik** räumt lose Dateien nach Kategorie in `Bilder/`, `Videos/`, `Audio/`, `Dokumente/`, `Archive/`, `Installer/`, `Disk-Images/` (bestehende Ordner wie `Pictures` oder `Documents` werden als Ziel erkannt, optional mit Jahres-Unterordner). Zusammenhängende Unterordner (mindestens 80 % eine Kategorie) wandern als Ganzes unter ihren Kategorie-Ordner, samt ihrer Hilfsdateien (Verknüpfungen, Thumbnails, Dotfiles). Gemischte Unterordner werden nur als Vorschlag zum Verteilen gezeigt. Begleitdateien wie `foto.jpg` + `foto.xmp` bleiben zusammen. Code und unbekannte Dateitypen bekommen kein Ziel, sie werden nur gezählt und bleiben liegen. Eine Vorher/Nachher-Ansicht zeigt die Struktur, bevor etwas passiert.

Nicht zerlegt werden Ordner, die ein Projekt enthalten oder Inhalte, die der Scan nicht erfasst hat (versteckt, ausgeschlossen, Verknüpfungen): beim Verschieben Datei für Datei bliebe sonst ein Teil zurück. Ist der gescannte Ordner selbst ein Kategorie-Ordner (zum Beispiel `Bilder`), bleibt Passendes liegen und alles andere erscheint nur als unsicherer Vorschlag. Unterordner von `Downloads` werden als Ganzes beurteilt, nur die lose darin liegenden Dateien einzeln.

Vor jedem Verschieben prüft tidyscan erneut, ob die Datei seit dem Scan unverändert ist und ob die erhaltene Duplikat-Kopie noch unverändert existiert. Alles landet wie gewohnt in der Quarantäne bzw. im Zielordner und ist über das Journal rückgängig machbar.

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
tidyscan undo --root <pfad>                       # neueste Sitzung mit Inhalt zurücknehmen
tidyscan undo <pfad>/.tidyscan-quarantine/<zeitstempel>/undo.json
tidyscan example-rules > rules.toml
```

Alle Scan-Befehle kennen `--skip-hidden`, `--exclude <GLOB>` (mehrfach) und `--max-depth N`. Ohne `--apply` wird nichts verändert. `--json` gibt den Vorschlag aus, zusammen mit `--apply` ein Objekt mit `proposal` und `report`. Der Bericht trennt *übersprungen* (die Platte passt nicht mehr zum Scan, nichts wurde angefasst) von *fehlgeschlagen* (ein Verschieben wurde versucht und ging schief).

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

- In Globs bleibt `*` innerhalb eines Ordners, nur `**` geht über Ordnergrenzen. `**/Screenshot*` trifft also Dateien, die so heißen, aber nicht alles unterhalb eines Ordners `Screenshots/`. `Downloads/*` meint die Dateien direkt in `Downloads`, `Downloads/**` auch die in Unterordnern.
- `move_to` ist relativ zum Scan-Ordner oder absolut (`D:/Archiv/{year}`, `/mnt/archiv/{year}`). Dateien ohne brauchbares Datum landen unter `unbekannt` statt in einem falschen Jahr.
- Regeln erreichen geschützte Bereiche nie und Projektordner nur mit `include_projects = true` in der Regel. Was deshalb ausgelassen wurde, wird gemeldet.

## Quarantäne

Verschobene Dateien und Ordner liegen unter `<Scan-Ordner>/.tidyscan-quarantine/<Zeitstempel>/` mit ihrer ursprünglichen relativen Struktur. Daneben liegt `undo.json`. Ein Undo stellt alles wieder her und überschreibt dabei nie etwas, was inzwischen am Originalpfad liegt. Fehlt eine Kopie in der Quarantäne, wird das als Konflikt gemeldet und nichts vorgetäuscht.

Jeder Lauf bekommt einen eigenen Sitzungsordner. Das Journal wird atomar geschrieben, die einzelnen Züge zusätzlich fortlaufend in `undo.log`: bricht ein Lauf mittendrin ab, ist trotzdem jeder bereits erfolgte Zug rückgängig machbar. Wird der gescannte Ordner später umbenannt oder verschoben, wandert die Quarantäne mit und Wiederherstellen legt alles am neuen Ort ab. Über Laufwerksgrenzen wird kopiert, geprüft und erst dann das Original entfernt.

Ganze Ordner samt Inhalt lassen sich in der Übersicht über "Ganzen Ordner in Quarantäne (Plan)" aufnehmen; sie werden als Einheit verschoben und als Einheit wiederhergestellt.

Der Tab **Quarantäne** listet alle Sitzungen mit Größe, lässt einzelne Einträge oder ganze Sitzungen wiederherstellen und ist die einzige Stelle, an der tidyscan Daten **endgültig löscht**, immer nach Rückfrage und nur innerhalb des Sitzungsordners, in dem das Journal liegt. Pfade aus dem Inhalt eines Journals bestimmen nie, was gelöscht wird, und ein Journal außerhalb eines Quarantäne-Ordners wird nicht angenommen. Auf der Kommandozeile:

```bash
tidyscan quarantine <pfad>                 # Sitzungen auflisten
tidyscan purge --root <pfad> [--all]       # zeigt, was gelöscht würde (ohne --all: die älteste Sitzung)
tidyscan purge --root <pfad> --all --yes   # löscht endgültig
```

Quarantänen, die beim Scannen eines Unterordners entstanden sind, zeigt der Tab gesondert an. Ein Ordner, der eine eigene Quarantäne enthält, wird nicht als Ganzes verschoben.

## Grenzen und Hinweise

- Symlinks, Junctions und Cloud-Platzhalter (OneDrive, iCloud "nur online") werden übersprungen und nicht mitgezählt.
- `$RECYCLE.BIN`, `System Volume Information`, `.Trashes`, `.Spotlight-V100` und die Quarantäne selbst werden nie gescannt.
- Zugriffszeiten sind auf den meisten Systemen unzuverlässig. tidyscan prüft das per Stichprobe und fällt auf das Änderungsdatum zurück.
- Hardlinks (mehrere Namen für dieselbe Datei) zählen nicht als Duplikate.
- Beim Verschieben ganzer Ordner auf ein anderes Laufwerk brechen Verknüpfungen im Ordner den Vorgang ab, damit nichts stillschweigend verloren geht.
- Ein abgebrochener Scan zeigt, was bis dahin gefunden wurde, liefert aber keine leeren Ordner und keinen Automatik-Vorschlag.
- Inhaltliches Gruppieren ("diese Dateien gehören zusammen") ist noch nicht enthalten.

## Entwicklung

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
```

Die Kernlogik liegt in `src/` als Bibliothek (`scan`, `analysis`, `age`, `dupes`, `context`, `triage`, `organize`, `rules`, `actions`), `cli.rs` und `ui/` sind dünne Schichten darüber.

## Lizenz

MIT
