use crate::PostureError;

pub(crate) fn get_serial_numbers_impl() -> Result<Vec<String>, PostureError> {
    Err(PostureError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_stub_returns_unsupported() {
        assert!(matches!(
            get_serial_numbers_impl(),
            Err(PostureError::UnsupportedPlatform)
        ));
    }
}
