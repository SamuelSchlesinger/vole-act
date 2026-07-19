#![allow(dead_code)]

/// Turn arbitrary fuzzer input into edits near a valid serialized artifact.
/// The raw-input branch retains broad parser coverage while the other modes
/// preserve enough structure to reach length, canonicality, and verifier
/// checks behind the outer wire header.
pub fn mutate_valid(base: &[u8], data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return base.to_vec();
    }

    let body = &data[1..];
    match data[0] % 6 {
        0 => body.to_vec(),
        1 => {
            let keep = read_usize(body).min(base.len());
            base[..keep].to_vec()
        }
        2 => {
            let mut out = base.to_vec();
            let (chunks, _) = body.as_chunks::<3>();
            for chunk in chunks.iter().take(128) {
                if !out.is_empty() {
                    let index = u16::from_le_bytes([chunk[0], chunk[1]]) as usize % out.len();
                    out[index] ^= chunk[2];
                }
            }
            out
        }
        3 => {
            let mut out = base.to_vec();
            let (chunks, _) = body.as_chunks::<3>();
            for chunk in chunks.iter().take(128) {
                if !out.is_empty() {
                    let index = u16::from_le_bytes([chunk[0], chunk[1]]) as usize % out.len();
                    out[index] = chunk[2];
                }
            }
            out
        }
        4 => {
            let mut out = base.to_vec();
            out.extend_from_slice(&body[..body.len().min(1024)]);
            out
        }
        _ => {
            let mut out = base.to_vec();
            if !out.is_empty() {
                let start = read_usize(body) % out.len();
                let width = read_usize(body.get(8..).unwrap_or_default())
                    .min(out.len().saturating_sub(start));
                out.drain(start..start + width);
            }
            out
        }
    }
}

pub fn read_u64(data: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    let take = data.len().min(bytes.len());
    bytes[..take].copy_from_slice(&data[..take]);
    u64::from_le_bytes(bytes)
}

pub fn read_u128(data: &[u8]) -> u128 {
    let mut bytes = [0u8; 16];
    let take = data.len().min(bytes.len());
    bytes[..take].copy_from_slice(&data[..take]);
    u128::from_le_bytes(bytes)
}

fn read_usize(data: &[u8]) -> usize {
    usize::try_from(read_u64(data)).unwrap_or(usize::MAX)
}
