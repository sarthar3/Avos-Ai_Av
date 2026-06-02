/// AVOS AI — Rust PE Parser
/// Fast PE/ELF binary parser exposed to Python via PyO3

use pyo3::prelude::*;
use std::collections::HashMap;
use std::fs;

#[derive(Debug)]
pub struct PeInfo {
    pub is_pe: bool,
    pub machine: u16,
    pub num_sections: u16,
    pub timestamp: u32,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub sections: Vec<SectionInfo>,
    pub entry_point: u32,
}

#[derive(Debug)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub characteristics: u32,
    pub entropy: f64,
}

/// Parse a PE file and return key metadata
#[pyfunction]
fn parse_pe(path: &str) -> PyResult<HashMap<String, PyObject>> {
    let data = fs::read(path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

    Python::with_gil(|py| {
        let mut result: HashMap<String, PyObject> = HashMap::new();

        // Check MZ header
        if data.len() < 64 || &data[0..2] != b"MZ" {
            result.insert("is_pe".to_string(), false.into_py(py));
            return Ok(result);
        }

        result.insert("is_pe".to_string(), true.into_py(py));

        // PE header offset at 0x3C
        if data.len() < 0x40 {
            return Ok(result);
        }
        let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;

        if data.len() < pe_offset + 24 {
            return Ok(result);
        }

        // Check PE signature
        if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
            result.insert("is_pe".to_string(), false.into_py(py));
            return Ok(result);
        }

        // COFF header starts at pe_offset + 4
        let coff = pe_offset + 4;
        let machine        = u16::from_le_bytes([data[coff],     data[coff + 1]]);
        let num_sections   = u16::from_le_bytes([data[coff + 2], data[coff + 3]]);
        let timestamp      = u32::from_le_bytes([data[coff + 4], data[coff + 5], data[coff + 6], data[coff + 7]]);
        let opt_header_size= u16::from_le_bytes([data[coff + 16], data[coff + 17]]);

        result.insert("machine".to_string(),       machine.into_py(py));
        result.insert("num_sections".to_string(),  num_sections.into_py(py));
        result.insert("timestamp".to_string(),     timestamp.into_py(py));
        result.insert("machine_name".to_string(),  machine_name(machine).into_py(py));

        // Optional header — entry point at offset 16 from start of optional header
        let opt_start = coff + 20;
        if data.len() > opt_start + 16 {
            let entry = u32::from_le_bytes([
                data[opt_start + 16], data[opt_start + 17],
                data[opt_start + 18], data[opt_start + 19],
            ]);
            result.insert("entry_point".to_string(), entry.into_py(py));
        }

        // Section headers
        let sections_start = opt_start + opt_header_size as usize;
        let mut sections_data: Vec<HashMap<String, PyObject>> = Vec::new();

        for i in 0..num_sections as usize {
            let sec_off = sections_start + i * 40;
            if data.len() < sec_off + 40 {
                break;
            }
            let name_bytes: Vec<u8> = data[sec_off..sec_off + 8]
                .iter().take_while(|&&b| b != 0).cloned().collect();
            let name = String::from_utf8_lossy(&name_bytes).to_string();
            let virtual_size  = u32::from_le_bytes([data[sec_off+8],  data[sec_off+9],  data[sec_off+10], data[sec_off+11]]);
            let raw_size      = u32::from_le_bytes([data[sec_off+16], data[sec_off+17], data[sec_off+18], data[sec_off+19]]);
            let raw_offset    = u32::from_le_bytes([data[sec_off+20], data[sec_off+21], data[sec_off+22], data[sec_off+23]]) as usize;
            let characteristics= u32::from_le_bytes([data[sec_off+36], data[sec_off+37], data[sec_off+38], data[sec_off+39]]);

            // Calculate section entropy
            let sec_end = (raw_offset + raw_size as usize).min(data.len());
            let entropy = if raw_offset < sec_end {
                calculate_entropy(&data[raw_offset..sec_end])
            } else {
                0.0
            };

            let mut sec_map: HashMap<String, PyObject> = HashMap::new();
            sec_map.insert("name".to_string(),           name.into_py(py));
            sec_map.insert("virtual_size".to_string(),   virtual_size.into_py(py));
            sec_map.insert("raw_size".to_string(),       raw_size.into_py(py));
            sec_map.insert("characteristics".to_string(),characteristics.into_py(py));
            sec_map.insert("entropy".to_string(),        entropy.into_py(py));
            sections_data.push(sec_map);
        }

        result.insert("sections".to_string(), sections_data.into_py(py));
        result.insert("file_size".to_string(), data.len().into_py(py));
        result.insert("file_entropy".to_string(), calculate_entropy(&data).into_py(py));

        Ok(result)
    })
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u64; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f64;
    counts.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = c as f64 / len;
        acc - p * p.log2()
    })
}

fn machine_name(machine: u16) -> &'static str {
    match machine {
        0x014C => "x86",
        0x8664 => "x86_64",
        0xAA64 => "ARM64",
        0x01C4 => "ARM",
        _      => "Unknown",
    }
}

/// Python module entry point
#[pymodule]
fn avos_parsers(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_pe, m)?)?;
    Ok(())
}
