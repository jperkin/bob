pub mod build;
pub mod history;
pub mod list;
pub mod rebuild;
pub mod sandbox;
pub mod simulate;
pub mod status;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Padded columns
    #[default]
    Table,
    /// Comma-separated values
    Csv,
    /// JSON array of objects
    Json,
}
