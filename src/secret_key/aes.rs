use generic_array::{
    typenum::{U16, U32},
    ArrayLength, GenericArray,
};

use super::AsSecretSlice;
use algorithm::{AES128GCM_ALG_ID, AES256GCM_ALG_ID};
use error::Error;

pub struct AesGcmKey<Length>(GenericArray<u8, Length>)
where
    Length: ArrayLength<u8>;

impl<Length> AesGcmKey<Length>
where
    Length: ArrayLength<u8>,
{
    /// Create a new AES-GCM key from the given byte array
    pub fn new(bytes: GenericArray<u8, Length>) -> Self {
        AesGcmKey(bytes)
    }

    /// Create a new AES-GCM key from the given slice, returning an error
    /// if it's the wrong length
    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        if slice.len() != Length::to_usize() {
            fail!(
                ParseError,
                "bad AES-{} key length: {} (expected {})",
                Length::to_usize() * 8,
                slice.len(),
                Length::to_usize()
            );
        }

        Ok(AesGcmKey::new(GenericArray::clone_from_slice(slice)))
    }
}

impl<Length> AsSecretSlice for AesGcmKey<Length>
where
    Length: ArrayLength<u8>,
{
    fn as_secret_slice(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<Length> Drop for AesGcmKey<Length>
where
    Length: ArrayLength<u8>,
{
    fn drop(&mut self) {
        use clear_on_drop::clear::Clear;
        self.0.as_mut().clear()
    }
}

/// AES-128 in Galois/Counter Mode (GCM)
pub type Aes128GcmKey = AesGcmKey<U16>;
impl_encodable_secret_key!(Aes128GcmKey, AES128GCM_ALG_ID);

/// AES-256 in Galois/Counter Mode (GCM)
pub type Aes256GcmKey = AesGcmKey<U32>;
impl_encodable_secret_key!(Aes256GcmKey, AES256GCM_ALG_ID);
