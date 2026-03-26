//! Functions for reading neural net info from disk.

use ndarray::Array3;
use serde_json::Value;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};
use swanky_error::{ErrorKind, Result, WrapErr, swanky_error};

fn value_to_array3(v: &Value) -> Result<Array3<i64>> {
    let rows = v
        .as_array()
        .ok_or_else(|| swanky_error!(ErrorKind::OtherError, "Cannot interpret value as array"))?;

    let data = rows
        .iter()
        .map(|cols| {
            if cols.is_array() {
                cols.as_array()
                    .unwrap() // We check that `cols.is_array()` so this `unwrap` should never fail.
                    .iter()
                    .map(|deps| {
                        if deps.is_array() {
                            deps.as_array()
                                .unwrap() // We check that `deps.is_array()` so this `unwrap` should never fail.
                                .iter()
                                .map(|val| {
                                    val.as_i64().ok_or_else(|| {
                                        swanky_error!(
                                            ErrorKind::OtherError,
                                            "Cannot interpret value as i64",
                                        )
                                    })
                                })
                                .collect::<Result<Vec<_>>>()
                        } else {
                            Ok(vec![deps.as_i64().ok_or_else(|| {
                                swanky_error!(
                                    ErrorKind::OtherError,
                                    "Cannot interpret value as i64",
                                )
                            })?])
                        }
                    })
                    .collect::<Result<Vec<_>>>()
            } else {
                Ok(vec![vec![cols.as_i64().ok_or_else(|| {
                    swanky_error!(ErrorKind::OtherError, "Cannot interpret value as i64")
                })?]])
            }
        })
        .collect::<Result<Vec<_>>>()?;

    let height = data.len();
    let width = data[0].len();
    let depth = data[0][0].len();

    Array3::from_shape_vec(
        (height, width, depth),
        data.into_iter().flatten().flatten().collect(),
    )
    .wrap_err(ErrorKind::OtherError, "Cannot create array from vec")
}

/// Read neural network tests from a directory.
///
/// The directory must contain either `tests.csv` or `tests.json`. The `num`
/// argument specifies the number of tests to return; `None` means return all
/// tests in the file.
pub fn read_tests(dir: &Path, num: Option<usize>) -> Result<Vec<Array3<i64>>> {
    let mut file = dir.join(Path::new("tests.json"));
    if !file.is_file() {
        file = dir.join(Path::new("tests.csv"));
        swanky_error::ensure!(
            file.is_file(),
            ErrorKind::FilesystemError,
            "Directory '{dir:?}' contains neither 'tests.json' nor 'tests.csv'"
        );
    }

    if file.extension().is_some_and(|ext| ext == "csv") {
        let reader = BufReader::new(
            File::open(&file).wrap_err_with(ErrorKind::FilesystemError, || {
                format!("Failed to open file '{file:?}'")
            })?,
        );
        // Note: csv can be at most 1-dimensional, if each image gets its own line
        let iter = reader.lines().map(|line| {
            let data = line
                .wrap_err(ErrorKind::OtherError, "Failed to read line")?
                .split(",")
                .map(|s| {
                    s.parse::<i64>()
                        .wrap_err(ErrorKind::OtherError, "Failed to parse string as `i64`")
                })
                .collect::<Result<Vec<_>>>()?;
            Array3::from_shape_vec((data.len(), 1, 1), data)
                .wrap_err(ErrorKind::OtherError, "Failed to convert `vec` to `Array3`")
        });

        if let Some(n) = num {
            iter.take(n).collect()
        } else {
            iter.collect()
        }
    } else if file.extension().is_some_and(|ext| ext == "json") {
        let file = File::open(&file).wrap_err_with(ErrorKind::FilesystemError, || {
            format!("Failed to open file '{:?}'", file)
        })?;
        let obj: Value = serde_json::from_reader(&file)
            .wrap_err_with(ErrorKind::OtherError, || {
                format!("Failed to read file '{file:?}' as JSON")
            })?;
        let iter = obj
            .as_array()
            .ok_or_else(|| swanky_error!(ErrorKind::OtherError, "Cannot interpret value as array"))?
            .iter()
            .map(value_to_array3);

        if let Some(n) = num {
            iter.take(n).collect()
        } else {
            iter.collect()
        }
    } else {
        swanky_error::bail!(
            ErrorKind::FilesystemError,
            "Unsupported filetype: \"{file:?}\""
        );
    }
}

/// Read neural network labels from a directory.
///
/// The directory must contain either `labels.csv` or `labels.json`.
pub fn read_labels(dir: &Path) -> Result<Vec<Vec<i64>>> {
    let mut file = dir.join(Path::new("labels.json"));
    if !file.is_file() {
        file = dir.join(Path::new("labels.csv"));
        swanky_error::ensure!(
            file.is_file(),
            ErrorKind::FilesystemError,
            "Directory '{dir:?}' contains neither 'labels.json' nor 'labels.csv'"
        );
    }

    if file.extension().is_some_and(|ext| ext == "csv") {
        let reader = BufReader::new(
            File::open(&file).wrap_err_with(ErrorKind::FilesystemError, || {
                format!("Failed to open file '{file:?}'")
            })?,
        );
        let vec = reader
            .lines()
            .map(|line| {
                let line: Result<Vec<_>> = line
                    .wrap_err(ErrorKind::OtherError, "Failed to read line")?
                    .split(",")
                    .map(|s| {
                        s.parse::<i64>()
                            .wrap_err(ErrorKind::OtherError, "Failed to covert string to `i64`")
                    })
                    .collect();
                line
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(vec)
    } else if file.extension().is_some_and(|ext| ext == "json") {
        let file = File::open(&file).wrap_err_with(ErrorKind::FilesystemError, || {
            format!("Failed to open file '{file:?}'")
        })?;
        let obj: Value = serde_json::from_reader(&file)
            .wrap_err_with(ErrorKind::OtherError, || {
                format!("Failed to read file '{file:?}' as JSON")
            })?;

        obj.as_array()
            .ok_or_else(|| swanky_error!(ErrorKind::OtherError, "Cannot interpret value as array"))?
            .iter()
            .map(|val| {
                val.as_array()
                    .ok_or_else(|| {
                        swanky_error!(ErrorKind::OtherError, "Cannot interpret value as array")
                    })?
                    .iter()
                    .map(|val| {
                        val.as_i64().ok_or_else(|| {
                            swanky_error!(ErrorKind::OtherError, "Cannot interpret value as i64")
                        })
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<_>>()
    } else {
        swanky_error::bail!(
            ErrorKind::FilesystemError,
            "Unsupported filetype: \"{file:?}\""
        );
    }
}
