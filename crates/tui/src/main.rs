use std::io::IsTerminal;

fn main() -> std::io::Result<()> {
    if !std::io::stdout().is_terminal() {
        println!("{}", bastion_core::app_name());
        return Ok(());
    }

    bastion_tui::run_terminal_app()
}
