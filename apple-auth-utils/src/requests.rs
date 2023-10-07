use std::{sync::Arc, fmt::Display};

#[derive(Debug, Clone)]
pub enum RequestErrorType {
    InvalidResponse,
    InvalidPList,
    RequestError {
        code: u16
    }
}

#[derive(Debug, Clone)]
pub struct RequestError {
    kind: RequestErrorType
}

impl Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            RequestErrorType::InvalidResponse => {
                f.write_str("Failed to read response")
            },
            RequestErrorType::InvalidPList => {
                f.write_str("Failed to parse plist")
            },
            RequestErrorType::RequestError { code } => {
                f.write_str(&format!("Request error with code {}", code))
            }
        }
    }
}

impl From<plist::Error> for RequestError {
    fn from(_: plist::Error) -> Self {
        Self {
            kind: RequestErrorType::InvalidPList
        }
    }
}

impl From<std::io::Error> for RequestError {
    fn from(_: std::io::Error) -> Self {
        Self {
            kind: RequestErrorType::InvalidResponse
        }
    }
}

impl From<ureq::Error> for RequestError {
    fn from(error: ureq::Error) -> Self {
        Self {
            kind: RequestErrorType::RequestError{
                code: error.into_response().map_or(0, |r| r.status())
            }
        }
    }
}

fn get_rustls_config_dangerous() -> Result<rustls::ClientConfig, rustls::Error> {
    let mut config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
  
    let mut dangerous_config = rustls::ClientConfig::dangerous(&mut config);
    dangerous_config.set_certificate_verifier(Arc::new(NoCertificateVerification {}));
  
    Ok(config)
}
  
struct NoCertificateVerification {}

impl rustls::client::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}
  
pub struct IDSRequests;

impl IDSRequests {
    pub fn request_session(request: Vec<u8>) -> Result<Vec<u8>, RequestError> {
        let pl = plist::from_value::<plist::Value>(&plist::Value::Data(request))?;
  
        let mut dict = plist::Dictionary::new();
        {
            dict.insert("session-info-request".into(), pl);
        }
  
        let mut bytes = Vec::<u8>::new();
        {
          plist::to_writer_xml(std::io::BufWriter::new(&mut bytes), &dict)?
        }
  
        let agent = ureq::AgentBuilder::new().tls_config(
          Arc::new(get_rustls_config_dangerous().expect("Failed to build rustls config"))).build();
  
        let mut reader = agent.post("https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/initializeValidation")
          .send_bytes(&bytes)?.into_reader();
        
        let mut bytes = Vec::<u8>::new();
        {
            reader.read_to_end(&mut bytes)?;
        }
        
        let dict = plist::from_bytes::<plist::Dictionary>(&bytes)?;
        let session_info = dict["session-info"].as_data();

        if let Some(bytes) = session_info {
            Ok(bytes.to_vec())
        }
        else {
            Err(RequestError {
                kind: RequestErrorType::InvalidResponse
            })
        }
    }

    pub fn request_certificate() -> Result<Vec<u8>, RequestError> {
        let mut reader = ureq::get("http://static.ess.apple.com/identity/validation/cert-1.0.plist")
            .call()?.into_reader();

        let mut bytes = Vec::<u8>::new();
        {
            reader.read_to_end(&mut bytes)?;
        }

        let dict = plist::from_bytes::<plist::Dictionary>(&bytes)?;
        let cert = dict["cert"].as_data();
        
        if let Some(bytes) = cert {
            Ok(bytes.to_vec())
        }
        else {
            Err(RequestError {
                kind: RequestErrorType::InvalidResponse
            })
        }
    }
}