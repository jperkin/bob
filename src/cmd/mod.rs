pub mod build;
pub mod history;
pub mod list;
pub mod rebuild;
pub mod sandbox;
pub mod simulate;
pub mod status;

use anyhow::{Result, bail};
use bob::try_println;

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

/**
 * Per-column display properties for tabular output.
 */
pub struct ColumnDef<'a> {
    pub name: &'a str,
    pub max_width: Option<usize>,
    pub right_align: bool,
}

impl<'a> ColumnDef<'a> {
    pub fn new(name: &'a str) -> Self {
        Self {
            name,
            max_width: None,
            right_align: false,
        }
    }
}

/**
 * Resolve column selection from user options, validating against known names.
 */
pub fn resolve_columns<'a>(
    columns: Option<&'a [String]>,
    long: bool,
    all_cols: &[&'a str],
    default_cols: &[&'a str],
) -> Result<Vec<&'a str>> {
    let cols: Vec<&str> = if columns.is_some() {
        columns
            .map(|c| c.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    } else if long {
        all_cols.to_vec()
    } else {
        default_cols.to_vec()
    };

    for col in &cols {
        if !all_cols.contains(col) {
            bail!(
                "Unknown column '{}'. Valid columns: {}",
                col,
                all_cols.join(", ")
            );
        }
    }

    Ok(cols)
}

/**
 * Render rows in the specified output format.
 *
 * This is the single implementation of Table/CSV/JSON rendering, used
 * by both `status` and `history` commands.
 */
pub fn render_output(
    format: OutputFormat,
    col_defs: &[ColumnDef],
    rows: &[Vec<String>],
    no_header: bool,
) -> Result<()> {
    let cols: Vec<&str> = col_defs.iter().map(|c| c.name).collect();

    match format {
        OutputFormat::Table => {
            let widths: Vec<usize> = col_defs
                .iter()
                .enumerate()
                .map(|(i, def)| {
                    let header_len = def.name.len();
                    let max_data = rows.iter().map(|r| r[i].len()).max().unwrap_or(0);
                    let w = header_len.max(max_data);
                    def.max_width.map_or(w, |mw| w.min(mw))
                })
                .collect();

            if !no_header {
                let header: Vec<String> = col_defs
                    .iter()
                    .zip(&widths)
                    .map(|(def, &w)| {
                        if def.right_align {
                            format!("{:>width$}", def.name.to_uppercase(), width = w)
                        } else {
                            format!("{:<width$}", def.name.to_uppercase(), width = w)
                        }
                    })
                    .collect();
                if !try_println(header.join("  ").trim_end()) {
                    return Ok(());
                }
            }

            for row in rows {
                let values: Vec<String> = col_defs
                    .iter()
                    .enumerate()
                    .zip(&widths)
                    .map(|((i, def), &w)| {
                        if def.right_align {
                            format!("{:>width$}", row[i], width = w)
                        } else {
                            format!("{:<width$}", row[i], width = w)
                        }
                    })
                    .collect();
                if !try_println(values.join("  ").trim_end()) {
                    break;
                }
            }
        }
        OutputFormat::Csv => {
            if !no_header && !try_println(&cols.join(",")) {
                return Ok(());
            }
            for row in rows {
                let values: Vec<String> = row
                    .iter()
                    .map(|v| {
                        if v.contains(',') || v.contains('"') {
                            format!("\"{}\"", v.replace('"', "\"\""))
                        } else {
                            v.clone()
                        }
                    })
                    .collect();
                if !try_println(&values.join(",")) {
                    break;
                }
            }
        }
        OutputFormat::Json => {
            let array: Vec<serde_json::Map<String, serde_json::Value>> = rows
                .iter()
                .map(|row| {
                    cols.iter()
                        .enumerate()
                        .map(|(i, &col)| {
                            (col.to_string(), serde_json::Value::String(row[i].clone()))
                        })
                        .collect()
                })
                .collect();
            try_println(&serde_json::to_string_pretty(&array)?);
        }
    }

    Ok(())
}
