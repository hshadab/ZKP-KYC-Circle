//! kyc_host <0xWallet> <kycStatus> <sigValid> [stepSize]
//! Proves Circle-style KYC approval: 5 Keccak limbs + 2 flags → return 0.

use std::{env, path::PathBuf, time::Instant};

use libc::{getrusage, rusage, RUSAGE_SELF};
use regex::Regex;
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
use bincode;
use hex;

/* ---- Nova type aliases --------------------------------------------- */
type E  = Bn256EngineIPA;
type EE = ipa_pc::EvaluationEngine<E>;
type S1 = BatchedSNARK<E, EE>;
type ED = Dual<E>;
type S2 = RelaxedSNARK<ED, ipa_pc::EvaluationEngine<ED>>;

/* ---- helpers -------------------------------------------------------- */
fn peak_rss_mb() -> f64 {
    let mut ru = rusage { ru_maxrss: 0, ..unsafe { core::mem::zeroed() } };
    unsafe { getrusage(RUSAGE_SELF, &mut ru) };
    #[cfg(target_os = "linux")] { ru.ru_maxrss as f64 / 1024.0 }
    #[cfg(target_os = "macos" )] { ru.ru_maxrss as f64 / (1024.0 * 1024.0) }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))] { 0.0 }
}

fn keccak_u32s(s: &str) -> [u32; 8] {
    let mut h = Keccak::v256();
    h.update(s.as_bytes());
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    let mut limbs = [0u32; 8];
    for (i, ch) in out.chunks(4).enumerate() {
        limbs[i] = u32::from_be_bytes(ch.try_into().unwrap());
    }
    limbs
}

/* ---- main ----------------------------------------------------------- */
fn main() -> anyhow::Result<()> {
    init_logger();

    /* parse CLI */
    let cli: Vec<String> = env::args().skip(1).collect();
    if cli.len() < 3 || cli.len() > 4 {
        eprintln!("USAGE  kyc_host <0xWallet> <kycStatus> <sigValid> [stepSize]");
        std::process::exit(1);
    }
    let wallet = &cli[0];
    let kyc: i32 = cli[1].parse()?;
    let sig: i32 = cli[2].parse()?;
    let step_sz: usize = cli.get(3).map(|s| s.parse().unwrap_or(8)).unwrap_or(8);

    /* validate inputs */
    let re = Regex::new(r"^0x[0-9a-fA-F]{40}$").unwrap();
    if !re.is_match(wallet) {
        eprintln!("Bad wallet string (0x + 40 hex chars)"); std::process::exit(1);
    }
    if kyc != 1 || sig != 1 {
        eprintln!("Proof of KYC approval failed."); std::process::exit(1);
    }

    /* compute 160-bit hash commitment */
    let h = keccak_u32s(wallet);          // 8 limbs, we use first 5

    /* build Wasm context */
    let mut args: Vec<String> = h[..5]
        .iter()
        .map(|&u| (u as i32).to_string())   // cast u32 → i32 (two’s-comp)
        .collect();
    args.extend([kyc.to_string(), sig.to_string()]);

    let wasm_args = WASMArgsBuilder::default()
        .file_path(PathBuf::from("examples/kyc_wasm.wasm"))?   // regular guest
        .invoke("check_kyc")
        .func_args(args)
        .build();
    let wasm_ctx = WASMCtx::new(wasm_args);

    /* Nova setup → prove → verify */
    let step = StepSize::new(step_sz);

    let t_setup = Instant::now();
    let pp = WasmSNARK::<E, S1, S2>::setup(step);
    let setup_s = t_setup.elapsed().as_secs_f64();

    let t_prove = Instant::now();
    let (snark, inst) = WasmSNARK::<E, S1, S2>::prove(&pp, &wasm_ctx, step)?;
    let prove_s = t_prove.elapsed().as_secs_f64();

    let t_verify = Instant::now();
    snark.verify(&pp, &inst)?;
    let verify_s = t_verify.elapsed().as_secs_f64();

    /* metrics */
    let rss_mb  = peak_rss_mb();
    let proof   = bincode::serialize(&snark)?;
    let preview = format!("{} … {}", hex::encode(&proof[..16]),
                                      hex::encode(&proof[proof.len() - 16..]));

    println!("\n──── Metrics ────────────────────────────────");
    println!("setup_sec  : {:.3}", setup_s);
    println!("prove_sec  : {:.3}", prove_s);
    println!("verify_sec : {:.3}", verify_s);
    println!("step_size  : {}",   step_sz);
    if rss_mb > 0.0 { println!("peak_rss   : {:.1} MB", rss_mb); }
    println!("proof_len  : {} bytes", proof.len());
    println!("proof_hex  : {}", preview);
    println!("─────────────────────────────────────────────");
println!("wallet     : {}", wallet);    
println!("✅ KYC proof verified");
    Ok(())
}
