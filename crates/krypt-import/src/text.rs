//! Turning file bytes into text. Exports come as UTF-8, with or without a byte order mark,
//! as UTF-16 from some Windows tools, and now and then in the old Windows code page.

use zeroize::Zeroizing;

pub(crate) fn decode(bytes: &[u8]) -> Zeroizing<String> {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return utf8_or_windows_1252(rest);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return utf16(rest, u16::from_le_bytes);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return utf16(rest, u16::from_be_bytes);
    }
    utf8_or_windows_1252(bytes)
}

fn utf8_or_windows_1252(bytes: &[u8]) -> Zeroizing<String> {
    match std::str::from_utf8(bytes) {
        Ok(text) => Zeroizing::new(text.to_owned()),
        Err(_) => Zeroizing::new(bytes.iter().map(|&byte| windows_1252(byte)).collect()),
    }
}

fn utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> Zeroizing<String> {
    let (pairs, _odd_byte) = bytes.as_chunks::<2>();
    let units = pairs.iter().map(|&pair| unit(pair));
    Zeroizing::new(
        char::decode_utf16(units)
            .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect(),
    )
}

/// Code page 1252 is Latin-1 except for 0x80 to 0x9F, where it has the euro sign, typographic
/// quotes and a few letters.
fn windows_1252(byte: u8) -> char {
    const HIGH: [char; 32] = [
        '\u{20ac}', '\u{81}', '\u{201a}', '\u{192}', '\u{201e}', '\u{2026}', '\u{2020}',
        '\u{2021}', '\u{2c6}', '\u{2030}', '\u{160}', '\u{2039}', '\u{152}', '\u{8d}', '\u{17d}',
        '\u{8f}', '\u{90}', '\u{2018}', '\u{2019}', '\u{201c}', '\u{201d}', '\u{2022}', '\u{2013}',
        '\u{2014}', '\u{2dc}', '\u{2122}', '\u{161}', '\u{203a}', '\u{153}', '\u{9d}', '\u{17e}',
        '\u{178}',
    ];
    match byte {
        0x80..=0x9F => HIGH[usize::from(byte - 0x80)],
        _ => char::from(byte),
    }
}
