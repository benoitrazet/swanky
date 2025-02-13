use std::{fs::File, io::Cursor};

use eyre::Result;
use merlin::Transcript;
use rand::thread_rng;
use schmivitz::{vole::functionality::{VoleProver, VoleVerifier}, Proof};
use std::io::Write;
use tempfile::tempdir;

// Get a fresh transcript
fn transcript() -> Transcript {
    Transcript::new(b"basic happy test transcript")
}

// Create a proof for the given circuit and input.
fn create_proof(
    circuit_bytes: &'static str,
    private_input_bytes: &'static str,
) -> (
    Result<Proof<VoleProver, VoleVerifier>>,
    Cursor<&'static [u8]>,
) {
    let circuit = Cursor::new(circuit_bytes.as_bytes());

    let dir = tempdir().unwrap();
    let private_input_path = dir.path().join("schmivitz_private_inputs");
    let mut private_input = File::create(private_input_path.clone()).unwrap();
    writeln!(private_input, "{}", private_input_bytes).unwrap();

    let rng = &mut thread_rng();

    (
        Proof::prove::<_, _>(
            &mut circuit.clone(),
            &private_input_path,
            &mut transcript(),
            rng,
        ),
        circuit,
    )
}

#[test]
fn prove_doesnt_explode() -> Result<()> {
    let mini_circuit_bytes = "version 2.0.0;
        circuit;
        @type field 2;
        @begin
          $0 <- @private(0);
          $1 <- @mul(0: $0, $0);
          $2 <- @add(0: $0, $0);
        @end ";
    let private_input_bytes = "version 2.0.0;
        private_input;
        @type field 2;
        @begin
            < 1 >;
        @end";

    let (proof, mut mini_circuit) = create_proof(mini_circuit_bytes, private_input_bytes);
    let verif = proof?.verify(&mut mini_circuit, &mut transcript());

    let failed = match verif {
        Ok(_) => { println!("yay!"); true} ,
        Err(ohno) => {println!("{}", ohno); false},
    };
    assert!(failed);

    Ok(())
}
