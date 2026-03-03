//! Functions for reading neural net info from disk.

use ndarray::Array3;
use serde_json::Value;
use std::io::{Error, ErrorKind, Result};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

fn value_to_array3(v: &Value) -> Result<Array3<i64>> {
    let rows = v.as_array().ok_or(Error::new(
        ErrorKind::InvalidData,
        "Cannot interpret value as array",
    ))?;

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
                                    val.as_i64().ok_or(Error::new(
                                        ErrorKind::InvalidData,
                                        "Cannot interpret value as i64",
                                    ))
                                })
                                .collect::<Result<Vec<_>>>()
                        } else {
                            Ok(vec![deps.as_i64().ok_or(Error::new(
                                ErrorKind::InvalidData,
                                "Cannot interpret value as i64",
                            ))?])
                        }
                    })
                    .collect::<Result<Vec<_>>>()
            } else {
                Ok(vec![vec![cols.as_i64().ok_or(Error::new(
                    ErrorKind::InvalidData,
                    "Cannot interpret value as i64",
                ))?]])
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
    .map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            format!("Cannot create array from vec: {e}"),
        )
    })
}

/// Read neural network tests from a directory.
///
/// The directory must contain either `tests.csv` or `tests.json`. The `num`
/// argument specifies the number of tests to return; `None` means return all
/// tests in the file.
pub fn read_tests(dir: &Path, num: Option<usize>) -> std::io::Result<Vec<Array3<i64>>> {
    let mut file = dir.join(Path::new("tests.json"));
    if !file.is_file() {
        file = dir.join(Path::new("tests.csv"));
        if !file.is_file() {
            return Err(Error::new(
                ErrorKind::InvalidFilename,
                "Given directory contains neither 'tests.json' nor 'tests.csv'",
            ));
        }
    }

    if file.extension().is_some_and(|ext| ext == "csv") {
        let reader = BufReader::new(File::open(file)?);
        // Note: csv can be at most 1-dimensional, if each image gets its own line
        let iter = reader.lines().map(|line| {
            let data = line?
                .split(",")
                .map(|s| {
                    s.parse::<i64>()
                        .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))
                })
                .collect::<Result<Vec<_>>>()?;
            Array3::from_shape_vec((data.len(), 1, 1), data)
                .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))
        });

        if let Some(n) = num {
            iter.take(n).collect()
        } else {
            iter.collect()
        }
    } else if file.extension().is_some_and(|ext| ext == "json") {
        let file = File::open(file)?;
        let obj: Value = serde_json::from_reader(file)?;
        let iter = obj
            .as_array()
            .ok_or(Error::new(
                ErrorKind::InvalidData,
                "Cannot interpret value as array",
            ))?
            .iter()
            .map(value_to_array3);

        if let Some(n) = num {
            iter.take(n).collect()
        } else {
            iter.collect()
        }
    } else {
        Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Unsupported filetype: \"{file:?}\""),
        ))
    }
}

/// Read neural network labels from a directory.
///
/// The directory must contain either `labels.csv` or `labels.json`.
pub fn read_labels(dir: &Path) -> Result<Vec<Vec<i64>>> {
    let mut file = dir.join(Path::new("labels.json"));
    if !file.is_file() {
        file = dir.join(Path::new("labels.csv"));
        if !file.is_file() {
            return Err(Error::new(
                ErrorKind::InvalidFilename,
                "Given directory contains neither 'labels.json' nor 'labels.csv'",
            ));
        }
    }

    if file.extension().is_some_and(|ext| ext == "csv") {
        let reader = BufReader::new(File::open(file)?);
        let vec = reader
            .lines()
            .map(|line| {
                let line: Result<Vec<_>> = line?
                    .split(",")
                    .map(|s| {
                        s.parse::<i64>()
                            .map_err(|e| Error::new(ErrorKind::InvalidData, e))
                    })
                    .collect();
                line
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(vec)
    } else if file.extension().is_some_and(|ext| ext == "json") {
        let file = File::open(file)?;
        let obj: Value = serde_json::from_reader(file)?;

        obj.as_array()
            .ok_or(Error::new(
                ErrorKind::InvalidData,
                "Cannot interpret value as array",
            ))?
            .iter()
            .map(|val| {
                val.as_array()
                    .ok_or(Error::new(
                        ErrorKind::InvalidData,
                        "Cannot interpret value as array",
                    ))?
                    .iter()
                    .map(|val| {
                        val.as_i64().ok_or(Error::new(
                            ErrorKind::InvalidData,
                            "Cannot interpret value as i64",
                        ))
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<_>>()
    } else {
        Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Unsupported filetype: \"{file:?}\""),
        ))
    }
}
