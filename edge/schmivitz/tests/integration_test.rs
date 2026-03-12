mod test {
    use merlin::Transcript;
    use rand::thread_rng;
    use schmivitz::{
        Proof,
        circuit::Circuit,
        circuit::load_circuit_from_strings_prover,
        vole::functionality::{VoleProver, VoleVerifier},
    };
    use std::sync::Once;
    use swanky_error::Result;
    use swanky_sieve_ir_codegen::compile_sieve_ir_str;

    static DO_LOGGING: bool = false;
    static INIT: Once = Once::new();

    fn init_logger() {
        INIT.call_once(|| {
            let _ =
                env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
                    .try_init();
        });
    }

    // Get a fresh transcript
    fn transcript() -> Transcript {
        Transcript::new(b"basic happy test transcript")
    }

    // Create a proof for the given circuit and input.
    fn create_proof(
        circuit_bytes: &'static str,
        private_input_bytes: &'static str,
    ) -> (Result<Proof<VoleProver, VoleVerifier>>, Circuit) {
        let circuit = load_circuit_from_strings_prover(circuit_bytes, private_input_bytes).unwrap();

        let rng = &mut thread_rng();

        let t = std::time::Instant::now();
        let t1 = Proof::prove_with_circuit::<_>(&circuit, &mut transcript(), rng);
        log::info!("proof time: {:?}", t.elapsed());
        (t1, circuit)
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

        let (proof, mini_circuit) = create_proof(mini_circuit_bytes, private_input_bytes);
        let verif = proof?.verify_with_circuit(&mini_circuit, &mut transcript());
        assert!(verif.is_ok());

        Ok(())
    }

    compile_sieve_ir_str!(
        DoesntExplode,
        "version 2.0.0;
        circuit;
        @type field 2;
        @begin
          $0 <- @private(0);
          $1 <- @mul(0: $0, $0);
          $2 <- @add(0: $0, $0);
        @end
    "
    );

    #[test]
    fn prove_sieveir_codegen() -> Result<()> {
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

        let (proof, mini_circuit) = create_proof(mini_circuit_bytes, private_input_bytes);
        let proof = proof.unwrap();
        let verif = proof.verify_with_circuit(&mini_circuit, &mut transcript());
        assert!(verif.is_ok());

        // Verify the dynamic circuit with the compiled circuit.
        let verif = proof.verify(DoesntExplode, &mut transcript());
        assert!(verif.is_ok());

        // Verify the compiled circuit with the dynamic circuit.
        let rng = &mut thread_rng();
        let max_wire_id = 2;
        let proof = Proof::<VoleProver, VoleVerifier>::prove(
            DoesntExplode,
            &mini_circuit.private_inputs,
            max_wire_id,
            &mut transcript(),
            rng,
        )
        .unwrap();
        let verif = proof.verify_with_circuit(&mini_circuit, &mut transcript());
        assert!(verif.is_ok());

        Ok(())
    }

    #[test]
    fn prove_addc_doesnt_explode() -> Result<()> {
        let mini_circuit_bytes = "version 2.0.0;
        circuit;
        @type field 2;
        @begin
          $0 <- @private(0);
          $1 <- @mul(0: $0, $0);
          $2 <- @add(0: $0, $0);
          $3 <- @addc(0: $0, < 1 >);
          $4 <- @private(0);
          $5 <- @mul(0: $3, $4);
          $6 <- @addc(0: $5, < 1 >);
        @end ";
        let private_input_bytes = "version 2.0.0;
        private_input;
        @type field 2;
        @begin
            < 1 >;
            < 1 >;
        @end ";

        let (proof, mini_circuit) = create_proof(mini_circuit_bytes, private_input_bytes);
        let verif = proof?.verify_with_circuit(&mini_circuit, &mut transcript());
        assert!(verif.is_ok());

        Ok(())
    }

    const SMALL_CIRCUIT: &str = "version 2.0.0;
    circuit;
    @type field 2;
    @begin
      $0 ... $4 <- @private(0);
      $5 <- @add(0: $0, $0);
      $6 <- @add(0: $0, $1);
      $7 <- @add(0: $0, $2);
      $8 <- @add(0: $0, $3);
      $9 <- @add(0: $0, $4);
      $10 <- @mul(0: $0, $5);
      $11 <- @mul(0: $0, $6);
      $12 <- @mul(0: $0, $7);
      $13 <- @mul(0: $0, $8);
      $14 <- @mul(0: $0, $9);
    @end ";

    #[test]
    fn prove_works_on_slightly_larger_circuit() -> Result<()> {
        let private_input_bytes = "version 2.0.0;
        private_input;
        @type field 2;
        @begin
            < 1 >;
            < 1 >;
            < 1 >;
            < 0 >;
            < 0 >;
        @end ";

        let (proof, small_circuit) = create_proof(SMALL_CIRCUIT, private_input_bytes);
        assert!(
            proof?
                .verify_with_circuit(&small_circuit, &mut transcript())
                .is_ok()
        );

        Ok(())
    }

    #[test]
    fn prove_aes256() -> Result<()> {
        if DO_LOGGING {
            init_logger();
        }

        let circuit_bytes = include_str!("../circuits/aes_256_conv.sieve");
        let private_input_bytes = include_str!("../circuits/aes_256_conv_private.sieve");

        let t = std::time::Instant::now();
        let circuit = load_circuit_from_strings_prover(circuit_bytes, private_input_bytes).unwrap();
        log::info!("parsing: {:?}", t.elapsed());

        let t = std::time::Instant::now();
        let rng = &mut thread_rng();
        let proof = Proof::<VoleProver, VoleVerifier>::prove_with_circuit::<_>(
            &circuit,
            &mut transcript(),
            rng,
        );
        log::info!("Elapsed prover   aes256: {:?}", t.elapsed());

        log::info!(
            "proof size estimate: {:?}",
            (proof.as_ref()).unwrap().proof_size_estimate()
        );

        let t = std::time::Instant::now();
        let verif = proof?.verify_with_circuit(&circuit, &mut transcript());
        assert!(verif.is_ok());
        log::info!("Elapsed verifier aes256: {:?}", t.elapsed());

        Ok(())
    }

    #[test]
    fn prove_sha256() -> Result<()> {
        // if log-level `RUST_LOG` not already set, then set to info
        if DO_LOGGING {
            init_logger();
        }
        let circuit_bytes = include_str!("../circuits/sha256_conv.sieve");
        let private_input_bytes = include_str!("../circuits/sha256_conv_private.sieve");

        let t = std::time::Instant::now();
        let circuit = load_circuit_from_strings_prover(circuit_bytes, private_input_bytes).unwrap();
        log::info!("parsing: {:?}", t.elapsed());

        let t = std::time::Instant::now();
        let rng = &mut thread_rng();
        let proof = Proof::<VoleProver, VoleVerifier>::prove_with_circuit::<_>(
            &circuit,
            &mut transcript(),
            rng,
        );
        log::info!("Elapsed prover   sha256: {:?}", t.elapsed());

        log::info!(
            "proof size estimate: {:?}",
            (proof.as_ref()).unwrap().proof_size_estimate()
        );

        let t = std::time::Instant::now();
        let verif = proof?.verify_with_circuit(&circuit, &mut transcript());
        assert!(verif.is_ok());
        log::info!("Elapsed verifier sha256: {:?}", t.elapsed());

        Ok(())
    }
}
