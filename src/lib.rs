
use pyo3::prelude::*;
use pyo3::exceptions::PyOSError;

use libsm::sm2::signature::SigCtx;
use libsm::sm2::encrypt::{EncryptCtx, DecryptCtx};

#[pyclass]
struct Keypair {
    pub pri_hex: String,
    pub pub_hex: String,
}

#[pymethods]
impl Keypair {
    #[new]
    fn new() -> Self {
        println!("new sig ctx");
        let ctx = SigCtx::new();
        println!("new pair");
        let (pk, sk) = ctx.new_keypair().unwrap();
        println!("dump");
        let pk_raw = ctx.serialize_pubkey(&pk, true).unwrap();
        let sk_raw = ctx.serialize_seckey(&sk).unwrap();
        // let s: String = String::from_utf8_lossy(&pk_raw).to_string();
        // let private_s: String = String::from_utf8_lossy(&sk_raw).to_string();
        let pub_hex = hex::encode(pk_raw);
        let pri_hex = hex::encode(sk_raw);
        println!("obj");
        Keypair {
            pri_hex,
            pub_hex,
        }
    }
    pub fn get_private_key_hex(&self) -> PyResult<String> {
        Ok(self.pri_hex.to_string())
    }

    pub fn get_public_key_hex(&self) -> PyResult<String> {
        Ok(self.pub_hex.to_string())
    }

    pub fn encrypt(&self, msg: String) -> PyResult<String> {
        let s = self.pub_hex.to_string();
        sm4_encrypt(s, msg)
    }

    pub fn decrypt(&self, hex_msg: String) -> PyResult<String> {
        let s = self.pri_hex.to_string();
        sm4_decrypt(s, hex_msg)
    }
}

#[pyfunction]
fn sm4_decrypt(prviate_key: String, hex_msg: String) -> PyResult<String> {
    let ctx = SigCtx::new();
    let private_k = hex::decode(prviate_key).map_err(|_| PyErr::new::<PyOSError, _>("Failed to decode hex"))?; 
    let private_raw = ctx.load_seckey(&private_k).map_err(|_| PyErr::new::<PyOSError, _>("Failed to load private key"))?;
    let msg = hex::decode(hex_msg).map_err(|_| PyErr::new::<PyOSError, _>("Failed to decode msg hex"))?; 
    let klen = msg.len() - 97;
    println!("klen is {}", klen);
    let decrtyp_ctx = DecryptCtx::new(klen, private_raw);
    let plain = decrtyp_ctx.decrypt(&msg).unwrap();
    Ok(String::from_utf8_lossy(&plain).to_string())
}

#[pyfunction]
fn sm4_encrypt(public_key: String, msg: String) -> PyResult<String> {
    let ctx = SigCtx::new();
    let s = public_key.to_string();
    let pub_k = hex::decode(s).map_err(|_| PyErr::new::<PyOSError, _>("Failed to decode hex"))?; 
    let pk_raw = ctx.load_pubkey(&pub_k).map_err(|_| PyErr::new::<PyOSError, _>("Failed to load public key"))?;
    let b_msg = msg.as_bytes();
    let klen = b_msg.len();
    let encrypt_ctx = EncryptCtx::new(klen, pk_raw);
    let cipher = encrypt_ctx.encrypt(b_msg).unwrap();
    Ok(hex::encode(cipher))
}


/// A Python module implemented in Rust. The name of this function must match
/// the `lib.name` setting in the `Cargo.toml`, else Python will not be able to
/// import the module.
#[pymodule]
fn libsmpy(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sm4_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(sm4_encrypt, m)?)?;
    m.add_class::<Keypair>()?;
    Ok(())
}
