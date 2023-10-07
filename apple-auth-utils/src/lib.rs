#![feature(concat_idents)]

extern crate libc;
extern crate plist;
extern crate serde;
extern crate serde_json;

mod requests;

use std::ffi::CString;
use std::fmt::Debug;
use serde::{Deserialize, Serialize};

macro_rules! wrap_call {
  ($n:ident($($p:ident: $t:ty),*)) => {
      
    #[link(name = "apple_crypto", kind = "static")]
    extern "C" {
      fn $n($($p: $t),*) -> NacError;
    }

    pub mod $n {
      use super::*;

      pub fn call($($p: $t),*) -> Result<(), super::NacError> {
        let err = unsafe {
          super::$n($($p),*)
        };
        if err != super::NacError::NacNoError {
          Err(err)
        }
        else {
          Ok(())
        }
      }
    }
  };
}

pub mod external {
  use serde::{Deserialize, Serialize};

  mod serde_str_array {
    use serde::{Deserialize, Serializer, Deserializer};
  
    pub fn serialize<const N: usize, S>(t: &[i8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer
    {
        unsafe {
          let unsigned: &[u8; N] = std::mem::transmute(t);
          let ser_tuple = serializer.serialize_str(&String::from_utf8_lossy(unsigned));
          ser_tuple
      }
    }
    
    pub fn deserialize<'de, const N: usize, S>(deserializer: S) -> Result<[i8; N], S::Error>
    where
        S: Deserializer<'de>
    {
        let ser_tuple = String::deserialize(deserializer)?;
  
        unsafe {
          let mut result: [i8; N] = [Default::default(); N];
  
          let slice = ser_tuple.as_bytes();
          let signed: &[i8] = std::mem::transmute(slice);
  
          result.copy_from_slice(&signed[..std::cmp::min(signed.len(), N)]);
  
          Ok(result)
        }
    }
  }

  pub const REQUEST_LEN: usize = 338;
  pub const CERTIFICATE_LEN: usize = 2385;
  pub const SESSION_DATA_LEN: usize = 698;

  #[repr(C)]
  #[derive(Serialize, Deserialize)]
  pub struct MachineInfo
  {
      #[serde(with = "serde_str_array")]
      pub board_id: [i8; 64],

      // boot uuid [uuid4]
      #[serde(with = "serde_str_array")]
      pub root_disk_uuid: [i8; 38],

      // product name [MacPro7,1]
      #[serde(with = "serde_str_array")]
      pub product_name: [i8; 64],

      // platform serial [uuid4]
      #[serde(with = "serde_str_array")]
      pub platform_serial: [i8; 38],

      // platform uuid [uuid4]
      #[serde(with = "serde_str_array")]
      pub platform_uuid: [i8; 38],
      
      // mlb [C02923200KVKN3YAG]
      #[serde(with = "serde_str_array")]
      pub mlb: [i8; 64],

      // rom  bytes
      pub rom: [u8; 6],

      // mac address bytes
      pub mac: [u8; 6],

      // Optional Gq3489ugfi
      pub platform_serial_encrypted: [u8; 17],

      // Optional Fyp98tpgj
      pub platform_uuid_encrypted: [u8; 17],

      // Optional kbjfrfpoJU
      pub root_disk_uuid_encrypted: [u8; 17],

      // Optional oycqAZloTNDm
      pub rom_encrypted: [u8; 17],

      // Optional abKPld1EcMni
      pub mlb_encrypted: [u8; 17],
  }

  #[repr(C)]
  #[derive(PartialEq, Debug)]
  pub enum NacError
  {
    NacNoError = 0,
    NacInvalidParameter = 1,
    NacInitError = 2,
    NacRequestError = 3,
    NacSignError = 4,
    NacEncryptError = 5
  }

  #[repr(C)]
  pub struct ValidationContext(pub *mut u8);

  impl Default for ValidationContext {
    fn default() -> Self {
        Self(std::ptr::null_mut())
    }
  }

  #[repr(C)]
  pub struct ValidationRequest(pub *mut u8);

  impl Default for ValidationRequest {
    fn default() -> Self {
        Self(std::ptr::null_mut())
    }
  }

  #[repr(C)]
  pub struct SessionData(pub [u8; SESSION_DATA_LEN]);
  
  #[repr(C)]
  pub struct ValidationSignature(pub *mut u8);

  impl Default for ValidationSignature {
    fn default() -> Self {
        Self(std::ptr::null_mut())
    }
  }

  #[repr(C)]
  pub struct ValidationCert(pub [u8; CERTIFICATE_LEN]);

  wrap_call!(build_machine_info(
    board_id: *const i8,
    root_disk_uuid: *const i8,
    product_name: *const i8,
    platform_serial: *const i8,
    platform_uuid: *const i8,
    mlb: *const i8,
    rom: *const i8,
    mac: *const i8,
    info: *mut MachineInfo
  ));

  wrap_call!(encrypt_io_data(
    data: *const u8, 
    size: u32, 
    output: *mut u8));

  wrap_call!(init_nac_request(
    cert: *const ValidationCert, 
    machine_info: *const MachineInfo, 
    out_context: *mut ValidationContext, 
    out_request: *mut ValidationRequest
  ));

  wrap_call!(sign_nac_request(
    context: ValidationContext, 
    session: *const SessionData,
    out_validation: *mut ValidationSignature,
    out_validation_length: *mut usize
  ));

  wrap_call!(free_nac(
    context: *mut ValidationContext
  ));

  wrap_call!(free_data(
    context: *mut u8
  ));

  impl Drop for ValidationContext {
    fn drop(&mut self) {
      unsafe {
        free_nac(self);
      }
    }
  }

  impl Drop for ValidationRequest {
    fn drop(&mut self) {
      unsafe {
        free_data(self.0);
      }
    }
  }

  impl Drop for ValidationSignature {
    fn drop(&mut self) {
      unsafe {
        free_data(self.0);
      }
    }
  }
}

use external::*;

#[derive(Serialize, Deserialize)]
pub struct RequiredSystemFields {
  board_id: CString,
  root_disk_uuid: CString,
  product_name: CString,
  platform_serial: CString,
  platform_uuid: CString,
  mlb: CString,
  rom: CString,
  mac: CString,
}

pub struct FieldLengthError {
  field: &'static str,
  length: usize
}

macro_rules! check_len_valid {
    ($self:ident, $x:ident, $max_len:literal) => {
        if $self.$x.as_bytes().len() == 0 || $self.$x.as_bytes().len() >= $max_len {
            return Some(FieldLengthError{
              field: stringify!($x), 
              length: $self.$x.as_bytes().len()
          })
        }
    };
}

impl RequiredSystemFields {
  pub fn check_error(&self) -> Option<FieldLengthError> {
    check_len_valid!(self, board_id, 64);
    check_len_valid!(self, root_disk_uuid, 64);
    check_len_valid!(self, product_name, 64);
    check_len_valid!(self, platform_serial, 38);
    check_len_valid!(self, platform_uuid, 38);
    check_len_valid!(self, mlb, 38);
    check_len_valid!(self, rom, 64);
    check_len_valid!(self, mac, 64);

    return None;
  } 
}

pub struct IDSValidator {
  machine_info: external::MachineInfo,
  cert: external::ValidationCert
}

pub enum IDSErrorType {
  NoError,
  InvalidJsonField(FieldLengthError),
  RequestError(requests::RequestError),
  NacError(NacError),
  InvalidJson(serde_json::Error)
}

pub struct IDSError {
  kind: IDSErrorType
}

impl std::fmt::Display for IDSError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as Debug>::fmt(&self, f) 
    }
}

impl Debug for IDSError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      match &self.kind {
        IDSErrorType::NoError => {
          f.write_str("No error")
        },
        IDSErrorType::InvalidJson(err) => {
          f.write_fmt(format_args!("Json error: {:?}", err))
        },
        IDSErrorType::RequestError(err) => {
          f.write_fmt(format_args!("Request error: {:?}", err))
        },
        IDSErrorType::NacError(err) => {
          f.write_fmt(format_args!("Nac error: {:?}", err))
        },
        IDSErrorType::InvalidJsonField(err) => {
          f.write_fmt(format_args!("Json error: Json field {} has invalid length: {}", err.field, err.length))
        }
      }
    }
}

impl IDSError {
  fn new(kind: IDSErrorType) -> Self {
    Self { kind }
  }
}

impl From<requests::RequestError> for IDSError {
    fn from(value: requests::RequestError) -> Self {
      Self {
        kind: IDSErrorType::RequestError(value)
      }
    }
}

impl From<serde_json::Error> for IDSError {
    fn from(value: serde_json::Error) -> Self {
      Self {
        kind: IDSErrorType::InvalidJson(value)
      }
    }
}

impl From<NacError> for IDSError {
    fn from(value: NacError) -> Self {
      Self {
        kind: IDSErrorType::NacError(value)
      }
    }
}

impl IDSValidator {
  pub fn from_json(js: &str, cert: Option<Vec<u8>>) -> Result<Self, IDSError> {
    let info: RequiredSystemFields = serde_json::from_str(js)?;
    Self::from_required_fields(&info, cert)
  }

  pub fn get_json(&self) -> Result<String, IDSError> {
    Ok(serde_json::to_string(&self.machine_info)?)
  }

  pub fn from_required_fields(info: &RequiredSystemFields, cert: Option<Vec<u8>>) -> Result<Self, IDSError> {
    if let Some(e) = info.check_error() {
      return Err(IDSError::new(IDSErrorType::InvalidJsonField(e)));
    }

    Ok(Self {
      machine_info: Self::create_machine_info(info)?,
      cert: ValidationCert(cert.ok_or(IDSError::new(IDSErrorType::NoError))
        .or_else(|_| requests::IDSRequests::request_certificate())?
        .try_into().expect("Invalid cert size"))
    })
  }

  pub fn from_system_info(info: MachineInfo, cert: Option<Vec<u8>>) -> Result<Self, IDSError> {
    Ok(Self {
      machine_info: info,
      cert: ValidationCert(cert.ok_or(IDSError::new(IDSErrorType::NoError))
        .or_else(|_| requests::IDSRequests::request_certificate())?
        .try_into().expect("Invalid cert size"))
    })
  }

  pub fn request_validation_data(&self) -> Result<Vec<u8>, IDSError> {
    unsafe {
      let mut context = ValidationContext::default();
      let mut request = ValidationRequest::default();

      init_nac_request::call(
        &self.cert, 
        &self.machine_info, 
        &mut context, 
        &mut request)?; 

      let session_data = SessionData(requests::IDSRequests::request_session(
        std::slice::from_raw_parts(request.0, REQUEST_LEN).to_vec())
        .expect("Failed to request session data").try_into()
        .expect("Invalid session size"));

      let mut validation_sig = ValidationSignature::default();
      let mut validation_len = 0usize;
      
      sign_nac_request::call(
        context, 
        &session_data, 
        &mut validation_sig, 
        &mut validation_len)?;
    
      let data = std::slice::from_raw_parts(validation_sig.0, validation_len);

      Ok(data.to_vec())
    }
  }

  pub fn encrypt_value<T: AsRef<[u8]>>(value: T) -> Option<Vec<u8>> {
    let slice = value.as_ref();
    let mut output: [u8; 17] = [0u8; 17];
    
    encrypt_io_data::call(slice.as_ptr(), slice.len() as u32, output.as_mut_ptr())
      .map(|_| output.to_vec()).ok()
  }
  
  fn create_machine_info(info: &RequiredSystemFields) -> Result<MachineInfo, NacError> {
    unsafe {
      let mut machine = std::mem::zeroed::<external::MachineInfo>();

      build_machine_info::call(
        info.board_id.as_ptr(),
        info.root_disk_uuid.as_ptr(),
        info.product_name.as_ptr(),
        info.platform_serial.as_ptr(),
        info.platform_uuid.as_ptr(),
        info.mlb.as_ptr(),
        info.rom.as_ptr(),
        info.mac.as_ptr(),
        &mut machine).map(|_| machine)
    }
  }
}

#[cfg(test)]
mod tests {
  use crate::external::*;
  use crate::*;

  #[test]
  fn test_ids() {
    let sample_data = r#"{
      "rom": "0C66833E0010",
      "board_id": "Mac-27AD2F918AE68F65",
      "product_name": "MacPro7,1",
      "mac": "5C:F7:FF:00:00:0F",
      "platform_serial": "F5KGCVYKP7QM",
      "mlb": "F5K925600QXFHDD1M",
      "root_disk_uuid": "6015372F-2EA0-4634-B85D-AEFB9E03DF00",
      "platform_uuid": "564D3AEF-EAF0-868D-B8B2-623A10E88A26"
    }"#;
    let ids = crate::IDSValidator::from_json(sample_data, None).expect("Failed to create ids");
    let validation_data = ids.request_validation_data().expect("Failed to obtain validation data");
    let js = ids.get_json().expect("Failed to obtain machine info json");
    assert!(validation_data.len() >= 389)
  }
  
  #[test]
  fn test_validation() {
    unsafe {
      let mut machine = std::mem::zeroed::<MachineInfo>();
      let rom = CString::new("0C66833E0010").unwrap();
      let board_id = CString::new("Mac-27AD2F918AE68F65").unwrap();
      let product_name = CString::new("MacPro7,1").unwrap();
      let mac = CString::new("5C:F7:FF:00:00:0F").unwrap();
      let io_platform_serial = CString::new("F5KGCVYKP7QM").unwrap();
      let mlb = CString::new("F5K925600QXFHDD1M").unwrap();
      let root_disk_uuid = CString::new("6015372F-2EA0-4634-B85D-AEFB9E03DF00").unwrap();
      let io_platform_uuid = CString::new("564D3AEF-EAF0-868D-B8B2-623A10E88A26").unwrap();
      
      build_machine_info::call(
        board_id.as_ptr(),
         root_disk_uuid.as_ptr(),
         product_name.as_ptr(),
         io_platform_serial.as_ptr(),
         io_platform_uuid.as_ptr(),
         mlb.as_ptr(),
         rom.as_ptr(),
         mac.as_ptr(),
          &mut machine).expect("Failed to build machine info");
  
      let cert = ValidationCert(requests::IDSRequests::request_certificate()
        .expect("Failed to request certificate").try_into()
        .expect("Invalid cert size"));
  
      let mut context = ValidationContext::default();
      let mut request = ValidationRequest::default();
  
      init_nac_request::call(&cert, &machine, &mut context, &mut request)
        .expect("Failed to init nac"); 
      
      let session_data = SessionData(requests::IDSRequests::request_session(
          std::slice::from_raw_parts(request.0, 338).to_vec())
        .expect("Failed to request session data").try_into()
        .expect("Invalid session size"));
      
      let mut validation_sig = ValidationSignature::default();
      let mut validation_len = 0usize;
      
      sign_nac_request::call(context, &session_data, &mut validation_sig, &mut validation_len)
        .expect("Failed to sign validation data");
    
      let data = std::slice::from_raw_parts(validation_sig.0, validation_len);
      assert!(data.len() >= 389);
    }
  }
  
  #[test]
  fn gen_machine() {
    unsafe {
      let mut machine = std::mem::zeroed::<MachineInfo>();
      let rom = CString::new("0C66833E0010").unwrap();
      let board_id = CString::new("Mac-27AD2F918AE68F65").unwrap();
      let product_name = CString::new("MacPro7,1").unwrap();
      let mac = CString::new("5C:F7:FF:00:00:0F").unwrap();
      let io_platform_serial = CString::new("F5KGCVYKP7QM").unwrap();
      let mlb = CString::new("F5K925600QXFHDD1M").unwrap();
      let root_disk_uuid = CString::new("6015372F-2EA0-4634-B85D-AEFB9E03DF00").unwrap();
      let io_platform_uuid = CString::new("564D3AEF-EAF0-868D-B8B2-623A10E88A26").unwrap();
      
      build_machine_info::call(
        board_id.as_ptr(),
         root_disk_uuid.as_ptr(),
         product_name.as_ptr(),
         io_platform_serial.as_ptr(),
         io_platform_uuid.as_ptr(),
         mlb.as_ptr(),
         rom.as_ptr(),
         mac.as_ptr(),
          &mut machine).expect("Failed to build machine info");
    }
  }
}