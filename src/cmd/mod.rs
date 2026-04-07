pub mod build;
pub mod db;
pub mod diff;
pub mod history;
pub mod list;
pub mod log;
pub mod publish;
pub mod rebuild;
pub mod sandbox;
pub mod simulate;
pub mod status;
pub mod util;

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
 * Column definition for tabular output.
 */
pub struct Col {
    pub name: String,
    pub align: bob::Align,
    pub max_width: usize,
}

impl Col {
    pub fn new(name: &str, align: bob::Align) -> Self {
        Self {
            name: name.to_string(),
            align,
            max_width: usize::MAX,
        }
    }

    pub fn max(mut self, w: usize) -> Self {
        self.max_width = w;
        self
    }
}

/**
 * Row formatter supporting table, CSV, and JSON output.
 */
pub struct Formatter {
    cols: Vec<Col>,
    rows: Vec<Vec<String>>,
}

impl Formatter {
    pub fn new(cols: Vec<Col>) -> Self {
        Self {
            cols,
            rows: Vec::new(),
        }
    }

    pub fn push(&mut self, row: Vec<String>) {
        self.rows.push(row);
    }

    pub fn print(self, format: OutputFormat, no_header: bool) {
        match format {
            OutputFormat::Table => self.print_table(no_header),
            OutputFormat::Csv => self.print_csv(no_header),
            OutputFormat::Json => self.print_json(),
        }
    }

    fn print_table(self, no_header: bool) {
        let widths: Vec<usize> = self
            .cols
            .iter()
            .enumerate()
            .map(|(i, col)| {
                let header_len = col.name.len();
                let max_data = self.rows.iter().map(|r| r[i].len()).max().unwrap_or(0);
                header_len.max(max_data).min(col.max_width)
            })
            .collect();

        if !no_header {
            let header: Vec<String> = self
                .cols
                .iter()
                .zip(&widths)
                .map(|(col, &w)| match col.align {
                    bob::Align::Right => format!("{:>width$}", col.name.to_uppercase(), width = w),
                    bob::Align::Left => format!("{:<width$}", col.name.to_uppercase(), width = w),
                })
                .collect();
            if !bob::try_println(header.join("  ").trim_end()) {
                return;
            }
        }

        for row in &self.rows {
            let values: Vec<String> = self
                .cols
                .iter()
                .enumerate()
                .zip(&widths)
                .map(|((i, col), &w)| match col.align {
                    bob::Align::Right => format!("{:>width$}", row[i], width = w),
                    bob::Align::Left => format!("{:<width$}", row[i], width = w),
                })
                .collect();
            if !bob::try_println(values.join("  ").trim_end()) {
                break;
            }
        }
    }

    fn print_csv(self, no_header: bool) {
        if !no_header {
            let header: Vec<&str> = self.cols.iter().map(|c| c.name.as_str()).collect();
            if !bob::try_println(&header.join(",")) {
                return;
            }
        }
        for row in &self.rows {
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
            if !bob::try_println(&values.join(",")) {
                break;
            }
        }
    }

    fn print_json(self) {
        let array: Vec<serde_json::Map<String, serde_json::Value>> = self
            .rows
            .iter()
            .map(|row| {
                self.cols
                    .iter()
                    .enumerate()
                    .map(|(i, col)| (col.name.clone(), serde_json::Value::String(row[i].clone())))
                    .collect()
            })
            .collect();
        bob::try_println(&serde_json::to_string_pretty(&array).unwrap_or_default());
    }
}
