use std::str::FromStr;

use generic_array::typenum::{U32, U8};
use generic_array::{ArrayLength, GenericArray};
use hex::FromHexError;
use sha2::{Digest, Sha256};


#[derive(Debug)]
pub struct DigestSha256(GenericArray<u8, U32>);

impl DigestSha256 {
    pub fn from_digestable<'a, A, I>(val: &'a A) -> DigestSha256
    where
        A: Digestable<'a, I>,
        I: Iterator<Item = &'a [u8]>,
    {
        let mut hasher = Sha256::new();
        for v in val.digestable() {
            hasher.update(v);
        }
        let res = hasher.finalize();
        DigestSha256(res)
    }
}

impl FromStr for DigestSha256 {
    type Err = FromHexError;

    fn from_str(s: &str) -> Result<DigestSha256, FromHexError> {
        let mut decoded: GenericArray<u8, U32> = Default::default();
        hex::decode_to_slice(s, &mut decoded)?;

        Ok(DigestSha256(decoded))
    }
}

pub trait Digestable<'a, I: Iterator<Item = &'a [u8]>> {
    /// Get an iterator over a data structure returning each
    /// field in sequence as a byte slice
    fn digestable(&'a self) -> I;
}

pub trait Digestable2<'a> {
    /// Get an iterator over a data structure returning each
    /// field in sequence as a byte slice
    fn digestable(&'a self) -> &'a [u8];
}

impl<'a> Digestable<'a, std::iter::Once<&'a [u8]>> for String {
    fn digestable(&'a self) -> std::iter::Once<&'a [u8]> {
        std::iter::once(self.as_bytes())
    }
}

struct OwnedOnce<'a> {
    slice: [u8; 8],
    slice_ref: Option<&'a [u8]>,
}

impl<'a> Iterator for OwnedOnce<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        self.slice_ref = Some(&self.slice);

        self.slice_ref
    }
}

impl<'a> Digestable<'a, OwnedOnce<'a>> for f64 {
    fn digestable(&'a self) -> OwnedOnce<'a> {
        let bytes = self.to_be_bytes();
        let iter = OwnedOnce { slice: bytes, slice_ref: None };

        iter
    }
}


impl<'a, A, B, IA, IB> Digestable<'a, std::iter::Chain<IA, IB>> for (A, B)
where
    A: Digestable<'a, IA>,
    B: Digestable<'a, IB>,
    IA: Iterator<Item = &'a [u8]>,
    IB: Iterator<Item = &'a [u8]>,
{
    fn digestable(&'a self) -> std::iter::Chain<IA, IB> {
        self.0.digestable().chain(self.1.digestable())
    }
}

/*
impl<'a, A> Digestable<'a, std::iter::Once<&'a [u8]>> for Vec<A>
where
    A: Digestable<'a, I>,
{
    fn digestable(&self) -> std::iter::Once<A> {
        self.iter().map(Digestable::digestable)
    }
}
*/
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_digest_256_from_sha256() {
        // Digest of an empty str
        let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        DigestSha256::from_str(sha256).expect("failed to decode");
    }

    #[test]
    fn test_hex_digest_256_from_sha256_uppercase() {
        // Digest of an empty str uppercase'd
        let sha256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";

        DigestSha256::from_str(sha256).expect("failed to decode");
    }

    #[test]
    fn test_string_as_digestable() {
        let some_string = "foobar".to_string();

        for s in some_string.digestable() {
            assert_eq!(s, some_string.as_bytes());
        }
    }

    // not sure this test makes sense as there is no error
    #[test]
    fn test_digest_from_string() {
        let some_string = "foobar".to_string();

        DigestSha256::from_digestable(&some_string);
    }

    #[test]
    fn test_digest_from_float() {
        let some_float: f64 = 0.0003;

        DigestSha256::from_digestable(&some_float);
    }

    #[test]
    fn test_digest_from_tuple() {
        let some_tuple = ("foo".to_string(), 0.003);

        DigestSha256::from_digestable(&some_tuple);
    }

    #[test]
    fn test_digest_from_vec() {
        let some_vec = vec!["foo".to_string(), "bar".to_string()];

        DigestSha256::from_digestable(&some_vec);
    }
}
