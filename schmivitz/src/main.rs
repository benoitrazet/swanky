#![allow(clippy::needless_range_loop)]
use schmivitz::parameters::REPETITION_PARAM;
use schmivitz::vole::commit_reconstruct::bitwise_f128b_from_f8b;
use schmivitz::vole::functionality::{
    compute_chall_2, create_voleith_prover, create_voleith_verifier, prove, verify, VoleithProver,
    VoleithVerifier,
};
use std::env;
use swanky_field::FiniteRing;
use swanky_field_binary::{F128b, F8b};

fn test_vole() {
    let how_many = 10_000_000;
    let t = std::time::Instant::now();
    let statement_sig = vec![1u8];
    let vole_creation = create_voleith_prover(&statement_sig, how_many);
    let VoleithProver {
        iv: _,
        decom: _,
        corrections: _,
        u,
        v,
        chall1,
        u_tilda,
        h_v,
    } = vole_creation.clone();
    let dummy_masked = vec![];
    let dummy_chall2 = compute_chall_2(&chall1, u_tilda, h_v, &dummy_masked);
    let dummy_a_tilda = F128b::ZERO;
    let dummy_b_tilda = F128b::ZERO;
    let sig = prove(
        vole_creation,
        dummy_masked,
        dummy_chall2,
        dummy_a_tilda,
        dummy_b_tilda,
    );

    let VoleithVerifier {
        d: _,
        q,
        chall2,
        chall3,
        delta,
        a_tilda,
    } = create_voleith_verifier(&statement_sig, sig, how_many);
    let b = verify(chall2, chall3, a_tilda, dummy_b_tilda);

    let mut vs = Vec::with_capacity(how_many);
    for _ in 0..how_many {
        vs.push([F8b::ZERO; REPETITION_PARAM]);
    }

    for pos in 0..how_many {
        for tau in 0..REPETITION_PARAM {
            vs[pos][tau] = v[tau][pos];
        }
    }
    let mut v_f128b: Vec<F128b> = Vec::with_capacity(how_many);
    for pos in 0..how_many {
        let val = bitwise_f128b_from_f8b(&vs[pos]);
        v_f128b.push(val);
    }

    for pos in 0..how_many {
        assert_eq!(v_f128b[pos] + u[pos] * delta, q[pos]);
    }

    println!("VOLE-it-Head completed in: {:?}", t.elapsed());
    assert!(b);
}

fn main() {
    // if log-level `RUST_LOG` not already set, then set to info
    match env::var("RUST_LOG") {
        Ok(val) => println!("loglvl: {}", val),
        Err(_) => env::set_var("RUST_LOG", "info"),
    };

    pretty_env_logger::init_timed();
    //grit()
    test_vole();
}
