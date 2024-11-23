use secret_sharing::vss::{RecoveryError, VSSShare};
use tonic::{transport::Server, Request, Response, Status};
use tokio::sync::oneshot;
use tokio::signal;

//pub mod sign;
use base64::{engine::general_purpose, Engine as _};

pub mod protos;
pub mod secret_sharing;
pub mod secure_channel;

use protos::derec_crypto::{
    EncryptDecryptRequest,
    EncryptDecryptResponse,
    EncryptEncryptRequest, 
    EncryptEncryptResponse,
    EncryptGenerateEncryptionKeyRequest, 
    EncryptGenerateEncryptionKeyResponse, 
    SignGenerateSigningKeyRequest,
    SignGenerateSigningKeyResponse,
    SignSignRequest,
    SignSignResponse, 
    SignVerifyRequest, 
    SignVerifyResponse, 
    VssShare,
    VssShareRequest,
    VssShareResponse,
    VssRecoverRequest,
    VssRecoverResponse,
    VssDetectErrorRequest,
    VssDetectErrorResponse,
    SiblingHash
};
use protos::derec_crypto::de_rec_cryptography_service_server::{DeRecCryptographyService, DeRecCryptographyServiceServer};
use tracing::{info,error};
use tracing_subscriber;

#[derive(Debug, Default)]
pub struct MyDeRecCryptographyService;


#[allow(non_upper_case_globals)]
const λ_bits: usize = 128;

#[allow(non_upper_case_globals)]
const λ: usize = λ_bits / 8;

#[tonic::async_trait]
impl DeRecCryptographyService for MyDeRecCryptographyService {
    async fn sign_generate_signing_key(
        &self,
        _request: Request<SignGenerateSigningKeyRequest>,
    ) -> Result<Response<SignGenerateSigningKeyResponse>, Status> {
        info!("sign_generate_signing_key");
        // Generate signing keys
        let (public_key, private_key) = secure_channel::sign::generate_signing_key();
        let pk_b64 = general_purpose::STANDARD.encode(&public_key);
        println!("PK: {pk_b64}");
        let response = SignGenerateSigningKeyResponse {
            public_key,
            private_key,
        };

        Ok(Response::new(response))
    }

    
    async fn sign_sign(
        &self,
        _request: Request<SignSignRequest>,
    ) -> Result<Response<SignSignResponse>, Status> {
        info!("sign_sign");
        // Generate signing keys
        let req = _request.into_inner(); // Extracts the actual message

        // Extract message and secret_key from SignRequest
        let message = req.message;
        let secret_key = req.secret_key;

        let signature = secure_channel::sign::sign(&message, &secret_key);
        let response = SignSignResponse {
            signature: signature
        };
        Ok(Response::new(response))
    }

    async fn sign_verify(
        &self,
        _request: Request<SignVerifyRequest>,
    ) -> Result<Response<SignVerifyResponse>, Status> {
        info!("sign_verify");
        // Generate signing keys
        let req = _request.into_inner(); // Extracts the actual message

        // Extract message and secret_key from SignRequest
        let message = req.message;
        let signature = req.signature;
        let public_key = req.public_key;

        let signed = secure_channel::sign::verify(&message, &signature, &public_key);
        let response = SignVerifyResponse {
            valid: signed
        };
        Ok(Response::new(response))
    }

    async fn encrypt_generate_encryption_key(
        &self,
        _request: Request<EncryptGenerateEncryptionKeyRequest>,
    ) -> Result<Response<EncryptGenerateEncryptionKeyResponse>, Status> {
        info!("encrypt_generate_encryption_key");
        // Generate signing keys
        let (public_key, private_key) = secure_channel::encrypt::generate_encryption_key();
        let pk_b64: String = general_purpose::STANDARD.encode(&public_key);
        println!("PK: {pk_b64}");
        let response = EncryptGenerateEncryptionKeyResponse {
            public_key,
            private_key,
        };

        Ok(Response::new(response))
    }

    async fn encrypt_encrypt(
        &self,
        _request: Request<EncryptEncryptRequest>,
    ) -> Result<Response<EncryptEncryptResponse>, Status> {
        info!("encrypt_encrypt");
        // Generate signing keys
        let req = _request.into_inner(); // Extracts the actual message

        // Extract message and secret_key from SignRequest
        let message = req.message;
        let public_key = req.public_key;

        let ciphertext = secure_channel::encrypt::encrypt(&message, &public_key);
        let response = EncryptEncryptResponse {
            ciphertext: ciphertext
        };
        Ok(Response::new(response))
    }

    async fn encrypt_decrypt(
        &self,
        _request: Request<EncryptDecryptRequest>,
    ) -> Result<Response<EncryptDecryptResponse>, Status> {
        info!("encrypt_decrypt");
        // Generate signing keys
        let req = _request.into_inner(); // Extracts the actual message

        // Extract message and secret_key from SignRequest
        let ciphertext = req.ciphertext;
        let secret_key = req.secret_key;

        let message = secure_channel::encrypt::decrypt(&ciphertext, &secret_key);
        let response = EncryptDecryptResponse {
            message: message
        };
        Ok(Response::new(response))
    }

    
    async fn vss_share(
        &self,
        _request: Request<VssShareRequest>,
    ) -> Result<Response<VssShareResponse>, Status> {
        info!("vss_share");
        // Generate signing keys
        let req = _request.into_inner(); // Extracts the actual message

        let t = req.t;
        let n = req.n;
        let message = req.message;
        let rand = vec_to_array_unchecked(req.rand);
        let access_structure: (u64, u64) = (t,n);

        let vss_shares = secret_sharing::vss::share(access_structure, &message, &rand);
        let mut shares : Vec<VssShare> = Vec::new();
        for vss_share in vss_shares {
            let mut merkle_path: Vec<SiblingHash> = Vec::new();

            for (is_left, hash) in vss_share.merkle_path {
                let sibling_hash = SiblingHash{
                    is_left : is_left,
                    hash: hash.clone()
                };
                
                merkle_path.push(sibling_hash);
            };
            // let us create a Protobuf DerecShare struct out of stuff in vss_share
            let derec_share = VssShare{
                encrypted_secret: vss_share.encrypted_secret.clone(),
                x : vss_share.x.clone(),
                y : vss_share.y.clone(),
                commitment : vss_share.commitment.clone(),
                merkle_path: merkle_path
            };
            shares.push(derec_share);
        }

        let response = VssShareResponse{
            shares: shares
        };
        Ok(Response::new(response))
    }

    
    async fn vss_recover(
        &self,
        _request: Request<VssRecoverRequest>,
    ) -> Result<Response<VssRecoverResponse>, Status> {
        info!("vss_recover");
        // Generate signing keys
        let req = _request.into_inner(); // Extracts the actual message

        let mut vss_shares: Vec<VSSShare> = Vec::new();
        for share in req.shares {
            let mut merkle_path : Vec<(bool, Vec<u8>)> = Vec::new();
            for path in share.merkle_path {
                merkle_path.push((
                    path.is_left,
                    path.hash
                ))
            }

            vss_shares.push(
                VSSShare { 
                    x: share.x, 
                    y: share.y, 
                    encrypted_secret: share.encrypted_secret, 
                    commitment: share.commitment, 
                    merkle_path: merkle_path
                }
            );
        }

        let result = secret_sharing::vss::recover(&vss_shares);
        let mut message: Vec<u8> = Vec::new();
        let mut err:i32 = protos::derec_crypto::RecoveryErrorType::NoError as i32;

        match result
        {
            Ok(recovered) => {
                message= recovered
            },
            Err(e) => {
                err = match e {
                    RecoveryError::InconsistentCommitments => protos::derec_crypto::RecoveryErrorType::InconsistentCommitments as i32,
                    RecoveryError::InconsistentCiphertexts => protos::derec_crypto::RecoveryErrorType::InconsistentCiphertexts as i32,
                    RecoveryError::CorruptShares => protos::derec_crypto::RecoveryErrorType::CorruptShares as i32,
                    RecoveryError::InsufficientShares => protos::derec_crypto::RecoveryErrorType::InsufficientShares as i32,
                };
                
            }
        }
        let response = VssRecoverResponse{
            message: message,
            error_type: err
        };
        Ok(Response::new(response))
    }

    async fn vss_detect_error(
        &self,
        _request: Request<VssDetectErrorRequest>,
    ) -> Result<Response<VssDetectErrorResponse>, Status> {
        info!("vss_detect_error");
        // Generate signing keys
        let req = _request.into_inner(); // Extracts the actual message

        let mut vss_shares: Vec<VSSShare> = Vec::new();
        for share in req.shares {
            let mut merkle_path : Vec<(bool, Vec<u8>)> = Vec::new();
            for path in share.merkle_path {
                merkle_path.push((
                    path.is_left,
                    path.hash
                ))
            }

            vss_shares.push(
                VSSShare { 
                    x: share.x, 
                    y: share.y, 
                    encrypted_secret: share.encrypted_secret, 
                    commitment: share.commitment, 
                    merkle_path: merkle_path
                }
            );
        }

        let result: Option<RecoveryError> = secret_sharing::vss::detect_error(&vss_shares);

        let err: i32 = match result {
            Some(RecoveryError::InconsistentCommitments) => protos::derec_crypto::RecoveryErrorType::InconsistentCommitments as i32,
            Some(RecoveryError::InconsistentCiphertexts) => protos::derec_crypto::RecoveryErrorType::InconsistentCiphertexts as i32,
            Some(RecoveryError::CorruptShares) => protos::derec_crypto::RecoveryErrorType::CorruptShares as i32,
            Some(RecoveryError::InsufficientShares) => protos::derec_crypto::RecoveryErrorType::InsufficientShares as i32,
            None => protos::derec_crypto::RecoveryErrorType::NoError as i32
        };
        
        let response = VssDetectErrorResponse{
            error_type: err
        };
        Ok(Response::new(response))
    }
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "0.0.0.0:50051".parse().unwrap();
    let service = MyDeRecCryptographyService::default();
    tracing_subscriber::fmt::init();

    info!("Server starting on {}", addr);

    // Start the tonic server

    // Create a oneshot channel for shutdown notification
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();


    // Spawn a task to listen for SIGINT and SIGTERM
    tokio::spawn(async move {

        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");

        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Received SIGINT (Ctrl+C), shutting down server...");
            }
            _ = sigterm.recv()  => {
                info!("Received SIGTERM, shutting down server...");
            }
        }
        let _ = shutdown_tx.send(());
    });

    let server_future = Server::builder()
        .add_service(DeRecCryptographyServiceServer::new(service))
        .serve_with_shutdown(addr, async {
            shutdown_rx.await.ok();
        });

    match server_future.await {
        Ok(_) => info!("Server stopped gracefully."),
        Err(err) => error!("Server error: {:?}", err),
    }

    Ok(())
}

fn vec_to_array_unchecked(vec: Vec<u8>) -> [u8; λ] {
    vec.try_into().unwrap() // Panics if the vector isn't exactly 16 elements
}


// fn vec_to_array_safe(vec: Vec<u8>) -> Option<[u8; λ]> {
//     if vec.len() == λ {
//         Some(vec.try_into().unwrap()) // Safe because length is checked
//     } else {
//         None
//     }
// }