use hmac_sha512::HMAC;
use bcrypt::{hash, verify};

const SECRET: &[u8; 14] = b"my_secret_test";
const COST: u32 = 12;

fn main() {
  let pwd = b"password";
  let hash = hash_pwd(pwd);
  let result = verify_pwd(pwd, &hash.as_str()).unwrap();
  println!("Hello world ! {}", result);
}

fn hash_pwd(password: &[u8]) -> String {
  let result = HMAC::mac(password, SECRET);
  println!("{:?}", result);
  let bcrypted = hash(result, COST);
  println!("{:?}", bcrypted);
  
  bcrypted.unwrap()
}

fn verify_pwd(password: &[u8], ref_hash: &str) -> Result<bool, bcrypt::BcryptError> {
  let result = HMAC::mac(password, SECRET);

  let bcrypted = verify(result, ref_hash);
  bcrypted 
}
  
#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_verify_hash_ok() {
        let password = b"password";
        let ref_hash = "$2b$12$oji1qZRHGv/UTyyT3RTKle69nvwoVERejziE8FICX39CheK7Qy/B6";
        let result = verify_pwd(password, ref_hash).unwrap();
        assert_eq!(result, true);
    }

    #[test]
    fn test_verify_hash_nok() {
        let not_password = b"not_my_password";
        let ref_hash = "$2b$12$oji1qZRHGv/UTyyT3RTKle69nvwoVERejziE8FICX39CheK7Qy/B6";
        let result = verify_pwd(not_password, ref_hash).unwrap();
        assert_eq!(result, false);
    }
}
