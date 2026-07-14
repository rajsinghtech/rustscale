use std::fs;

use crate::{dedup_serials, is_sentinel_serial, PostureError};

const DMI_SERIAL_PATHS: [&str; 3] = [
    "/sys/class/dmi/id/product_serial",
    "/sys/class/dmi/id/board_serial",
    "/sys/class/dmi/id/chassis_serial",
];

pub(crate) fn get_serial_numbers_impl() -> Result<Vec<String>, PostureError> {
    let serials = DMI_SERIAL_PATHS
        .iter()
        .filter_map(|path| fs::read_to_string(path).ok())
        .map(|serial| serial.trim().to_string())
        .filter(|serial| !is_sentinel_serial(serial))
        .collect();
    let serials = dedup_serials(serials);

    if serials.is_empty() {
        Err(PostureError::CollectionFailed("no DMI serial found".into()))
    } else {
        Ok(serials)
    }
}

#[cfg(test)]
mod tests {
    use crate::{dedup_serials, is_sentinel_serial};

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
            .filter(|serial| !is_sentinel_serial(serial))
            .map(ToString::to_string)
            .collect();

        assert_eq!(
            dedup_serials(serials),
            vec!["product-serial", "board-serial"]
        );
    }
}
