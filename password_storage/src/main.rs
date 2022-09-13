use sha2::Sha256;
use hmac::{Hmac, Mac};
use hex_literal::hex;
use bcrypt::{hash, verify}

type HmacSha256 = Hmac<Sha256>;

const SECRET = b"my_secret_test";
const COST: u32 = 12;

fn main() {
  println!("Hello world !");
}

fn hash_pwd(password: String) -> String {

  let mut mac = HmacSha256::new_from_slice(SECRET)
      .expect("HMAC can take key of any size");
  mac.update(password);
  // `result` has type `CtOutput` which is a thin wrapper around array of
  // bytes for providing constant time equality check
  let result = mac.finalize();
  // To get underlying array use `into_bytes`, but be careful, since
  // incorrect use of the code value may permit timing attacks which defeats
  // the security provided by the `CtOutput`
  let code_bytes = result.into_bytes();
  
  let bcrypted = hash(code_bytes, COST);
  
  crypted
}

fn verify_pwd(password: String, ref_hash: String) -> Result<u32, u32> {
  
  let mut mac = HmacSha256::new_from_slice(SECRET)
      .expect("HMAC can take key of any size");
  mac.update(password);
  // `result` has type `CtOutput` which is a thin wrapper around array of
  // bytes for providing constant time equality check
  let result = mac.finalize();
  // To get underlying array use `into_bytes`, but be careful, since
  // incorrect use of the code value may permit timing attacks which defeats
  // the security provided by the `CtOutput`
  let code_bytes = result.into_bytes();
  
  let bcrypted = verify(code_bytes, ref_hash);
  Ok(0)  
}
  
#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_create_hash() {
        let password = String::new();
        let hashed = hash_pwd(password);
        let ref_hash = String::new();
        assert_eq!(hashed, ref_hash);
    }

    #[test]
    fn test_verify_hash() {
        // This assert would fire and test will fail.
        // Please note, that private functions can be tested too!
        let password = String::new();
        let ref_hash = String::new();
        let result = verify_pwd(password, ref_hash);
        assert_eq!(verify, Ok(0);
    }
}
