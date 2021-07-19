
use tokio_rustls::rustls::Certificate;
use x509_parser::prelude::*;

#[derive(Debug)]
pub enum CNExtractionError {
    BadDER,
    UnsupportedCertVersion,
    BadCommonName
}

impl std::fmt::Display for CNExtractionError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            &Self::BadDER => write!(f, "Bad DER"),
            &Self::UnsupportedCertVersion => write!(f, "Unsupported certificate version"),
            &Self::BadCommonName => write!(f, "Common name has bad format or missing"),
        }
    }
}

impl std::error::Error for CNExtractionError {}

pub fn extract_cn_from_presented_certificates(presented_certs: &[Certificate]) -> Result<String, CNExtractionError>{
    let res = parse_x509_certificate(&presented_certs[0].0);
    match res {
        Ok((rem, cert)) => {
            if !rem.is_empty() {
                return Err(CNExtractionError::BadDER);
            }
            if cert.tbs_certificate.version != X509Version::V3 {
                return Err(CNExtractionError::UnsupportedCertVersion);
            }
            debug!(
                "Certificate\n Subject {},\n Issuer {}",
                cert.tbs_certificate.subject, cert.tbs_certificate.issuer
            );
            let cn:&str = cert
                .tbs_certificate
                .subject
                .iter_common_name()
                .next().ok_or(CNExtractionError::BadCommonName)?
            .as_str().map_err(|_| CNExtractionError::BadCommonName)?;
            Ok(cn.to_owned())
        },
        _ => Err(CNExtractionError::BadDER)
    }

}
