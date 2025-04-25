//! HTTP wrapper around the KYC proof.
//! POST /prove  { wallet, kyc, sig_valid, step? }

use axum::{
    extract::State,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc, time::Instant};
use tokio::signal;

use tiny_keccak::{Hasher, Keccak};
use zk_engine::{
    utils::logging::init_logger,
    wasm_ctx::{WASMArgsBuilder, WASMCtx},
    wasm_snark::{StepSize, WasmSNARK},
    nova::{
        provider::{ipa_pc, Bn256EngineIPA},
        spartan::{
            batched::BatchedRelaxedR1CSSNARK as BatchedSNARK,
            snark::RelaxedR1CSSNARK          as RelaxedSNARK,
        },
        traits::Dual,
    },
};
use anyhow::Result;
use hex;
use bincode;

/* ---------- Nova type aliases ------------------------------------ */
type  E  = Bn256EngineIPA;
type  EE = ipa_pc::EvaluationEngine<E>;
type  S1 = BatchedSNARK<E, EE>;
type  ED = Dual<E>;
type  S2 = RelaxedSNARK<ED, ipa_pc::EvaluationEngine<ED>>;

/* ---------- request / response structs --------------------------- */
#[derive(Deserialize)]
struct ProveRequest {
    wallet:    String,
    kyc:       i32,
    sig_valid: i32,
    #[serde(default = "default_step")]
    step:      usize,
}
fn default_step() -> usize { 8 }

#[derive(Serialize)]
struct ProveResponse {
    setup_sec:  f64,
    prove_sec:  f64,
    verify_sec: f64,
    proof_len:  usize,
    proof_hex:  String,
}

/* ---------- main ------------------------------------------------- */
#[tokio::main]
async fn main() -> Result<()> {
    init_logger();

    let app = Router::new()
        .route("/prove", post(handle_prove))
        .with_state(Arc::new(()));

    tracing::info!("🚀 zk_server listening on http://0.0.0.0:8080");
    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

async fn shutdown() {
    signal::ctrl_c().await.ok();
    tracing::info!("shutdown");
}

/* ---------- handler ---------------------------------------------- */
async fn handle_prove(
    State(_): State<Arc<()>>,
    Json(req): Json<ProveRequest>,
) -> impl IntoResponse {
    match prove(req).await {
        Ok(resp)  => (axum::http::StatusCode::OK,   Json(resp)).into_response(),
        Err(err)  => (axum::http::StatusCode::BAD_REQUEST, Json(err.to_string())).into_response(),
    }
}

/* ---------- proof routine ---------------------------------------- */
async fn prove(req: ProveRequest) -> Result<ProveResponse> {
    /* 0. Early fail-fast guard */
    if req.kyc != 1 || req.sig_valid != 1 {
        anyhow::bail!("Proof of KYC approval failed.");
    }

    /* 1. Compute 5 Keccak limbs of the wallet string */
    let limbs = {
        let mut k = Keccak::v256();
        k.update(req.wallet.as_bytes());
        let mut out = [0u8; 32];
        k.finalize(&mut out);
        let mut v = [0i32; 5];
        for (i, chunk) in out.chunks(4).take(5).enumerate() {
            v[i] = i32::from_be_bytes(chunk.try_into()?);
        }
        v
    };

    /* 2. Build Wasm ctx (7 args) */
    let mut args: Vec<String> = limbs.iter().map(|x| x.to_string()).collect();
    args.extend([req.kyc.to_string(), req.sig_valid.to_string()]);

    let wasm_args = WASMArgsBuilder::default()
        .file_path(PathBuf::from("examples/kyc_wasm.wasm"))?
        .invoke("check_kyc")
        .func_args(args)
        .build();
    let wasm_ctx = WASMCtx::new(wasm_args);

    /* 3. Nova setup → prove → verify */
    let step  = StepSize::new(req.step);
    let t0    = Instant::now();
    let pp    = WasmSNARK::<E,S1,S2>::setup(step);
    let setup = t0.elapsed().as_secs_f64();

    let t1    = Instant::now();
    let (snark, inst) = WasmSNARK::<E,S1,S2>::prove(&pp,&wasm_ctx,step)?;
    let prove = t1.elapsed().as_secs_f64();

    let t2    = Instant::now();
    snark.verify(&pp,&inst)?;
    let verify= t2.elapsed().as_secs_f64();

    /* 4. Serialize preview */
    let proof = bincode::serialize(&snark)?;
    let preview = format!("{}…{}",
        hex::encode(&proof[..16]),
        hex::encode(&proof[proof.len()-16..]));

    Ok(ProveResponse {
        setup_sec:  setup,
        prove_sec:  prove,
        verify_sec: verify,
        proof_len:  proof.len(),
        proof_hex:  preview,
    })
}
