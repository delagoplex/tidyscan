use clap::Parser;

fn main() {
    let cli = tidyscan::cli::Cli::parse();
    match tidyscan::cli::run(cli) {
        Ok(Some(path)) => {
            if let Err(e) = tidyscan::ui::run(path) {
                eprintln!("GUI konnte nicht gestartet werden: {e}");
                std::process::exit(1);
            }
        }
        Ok(None) => {}
        Err(e) => {
            eprintln!("Fehler: {e:#}");
            std::process::exit(1);
        }
    }
}
