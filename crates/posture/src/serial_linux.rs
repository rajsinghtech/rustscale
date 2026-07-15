use std::fs::File;
use std::io::Read;

use crate::{dedup_serials, is_sentinel_serial, PostureError, MAX_SERIAL_LEN};

const DMI_SERIAL_PATHS: [&str; 3] = [
    "/sys/class/dmi/id/product_serial",
    "/sys/class/dmi/id/board_serial",
    "/sys/class/dmi/id/chassis_serial",
];

pub(crate) fn get_serial_numbers_impl() -> Result<Vec<String>, PostureError> {
    let mut serials = Vec::with_capacity(DMI_SERIAL_PATHS.len());
    let mut saw_io_error = None;
    for path in DMI_SERIAL_PATHS {
        match read_bounded(path) {
            Ok(serial) if !is_sentinel_serial(&serial) => serials.push(serial),
            Ok(_) => {}
            Err(error) => saw_io_error = Some(error),
        }
    }
    let serials = dedup_serials(serials);
    if !serials.is_empty() {
        Ok(serials)
    } else {
        Err(saw_io_error.unwrap_or(PostureError::CollectionFailed))
    }
}

fn read_bounded(path: &str) -> Result<String, PostureError> {
    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity(MAX_SERIAL_LEN + 1);
    file.take((MAX_SERIAL_LEN + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SERIAL_LEN {
        return Err(PostureError::InvalidData);
    }
    let value = std::str::from_utf8(&bytes).map_err(|_| PostureError::InvalidData)?;
    let value = value.trim();
    if value.chars().any(char::is_control) || value.is_empty() {
        return Err(PostureError::InvalidData);
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use crate::{dedup_serials, is_sentinel_serial, MAX_SERIALS};

    #[test]
    fn serial_linux_dmi_parsing() {
        let values = [
            "product-serial",
            "To Be Filled By O.E.M.",
            "product-serial",
            "board-serial",
        ];
        let serials = values
            .iter()
            .take(MAX_SERIALS)
            .filter(|serial| !is_sentinel_serial(serial))
            .map(ToString::to_string)
            .collect();

        assert_eq!(
            dedup_serials(serials),
            vec!["product-serial", "board-serial"]
        );
    }
}
