use std::io::IsTerminal;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AppSurface {
    Tui,
}

fn main() -> std::io::Result<()> {
    match default_surface() {
        AppSurface::Tui => run_tui(),
    }
}

fn default_surface() -> AppSurface {
    AppSurface::Tui
}

fn run_tui() -> std::io::Result<()> {
    if !std::io::stdout().is_terminal() {
        println!("{}", bastion_core::app_name());
        return Ok(());
    }

    bastion_tui::run_terminal_app()
}

#[cfg(test)]
mod tests {
    use super::{AppSurface, default_surface};

    #[test]
    fn root_binary_defaults_to_tui_surface() {
        assert_eq!(AppSurface::Tui, default_surface());
    }
}
