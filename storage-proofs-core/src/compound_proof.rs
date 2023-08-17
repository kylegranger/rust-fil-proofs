use anyhow::{ensure, Context};
use bellperson::{
    groth16::{
        self,
        aggregate::{
            aggregate_proofs, verify_aggregate_proof, AggregateProof, ProverSRS, VerifierSRS,
        },
        create_random_proof_batch, create_random_proof_batch_in_priority, verify_proofs_batch,
        PreparedVerifyingKey, MappedParameters,
    },
    Circuit,
};
use blstrs::{Bls12, Scalar as Fr};
use log::info;

use std::path::Path;
use serde_json::json;
use serde::{Serialize, Deserialize};
use rand::{rngs::OsRng, RngCore};
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};

use crate::{
    error::Result,
    multi_proof::MultiProof,
    parameter_cache::{CacheableParameters, ParameterSetMetadata},
    partitions::partition_count,
    proof::ProofScheme,
};

#[derive(Clone)]
pub struct SetupParams<'a, S: ProofScheme<'a>> {
    pub vanilla_params: <S as ProofScheme<'a>>::SetupParams,
    pub partitions: Option<usize>,
    /// High priority (always runs on GPU) == true
    pub priority: bool,
}


#[derive(Default, Clone, Serialize, Deserialize, Debug)]
pub struct FilecoinDeployment {
    pub circuits: String,
    pub groth_params: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PublicParams<'a, S: ProofScheme<'a>> {
    pub vanilla_params: S::PublicParams,
    pub partitions: Option<usize>,
    pub priority: bool,
}

/// CircuitComponent exists so parent components can pass private inputs to their subcomponents
/// when calling CompoundProof::circuit directly. In general, there are no internal private inputs,
/// and a default value will be passed. CompoundProof::circuit implementations should exhibit
/// default behavior when passed a default ComponentPrivateinputs.
pub trait CircuitComponent {
    type ComponentPrivateInputs: Default + Clone;
}

/// The CompoundProof trait bundles a proof::ProofScheme and a bellperson::Circuit together.
/// It provides methods equivalent to those provided by proof::ProofScheme (setup, prove, verify).
/// See documentation at proof::ProofScheme for details.
/// Implementations should generally only need to supply circuit and generate_public_inputs.
/// The remaining trait methods are used internally and implement the necessary plumbing.
pub trait CompoundProof<'a, S: ProofScheme<'a>, C: Circuit<Fr> + CircuitComponent + Send>
where
    S::Proof: Sync + Send,
    S::PublicParams: ParameterSetMetadata + Sync + Send,
    S::PublicInputs: Clone + Sync,
    Self: CacheableParameters<C, S::PublicParams>,
{
    // setup is equivalent to ProofScheme::setup.
    fn setup(sp: &SetupParams<'a, S>) -> Result<PublicParams<'a, S>> {
        Ok(PublicParams {
            vanilla_params: S::setup(&sp.vanilla_params)?,
            partitions: sp.partitions,
            priority: sp.priority,
        })
    }

    fn partition_count(public_params: &PublicParams<'a, S>) -> usize {
        match public_params.partitions {
            None => 1,
            Some(0) => panic!("cannot specify zero partitions"),
            Some(k) => k,
        }
    }

    /// prove is equivalent to ProofScheme::prove.
    fn prove<'b>(
        pub_params: &PublicParams<'a, S>,
        pub_in: &S::PublicInputs,
        priv_in: &S::PrivateInputs,
        groth_params: &'b groth16::MappedParameters<Bls12>,
    ) -> Result<MultiProof<'b>> {
        let partition_count = Self::partition_count(pub_params);
        println!("asdf: prove, in compound_proof.rs");

        // This will always run at least once, since there cannot be zero partitions.
        ensure!(partition_count > 0, "There must be partitions");

        info!("vanilla_proofs:start");
        let vanilla_proofs =
            S::prove_all_partitions(&pub_params.vanilla_params, pub_in, priv_in, partition_count)?;

        info!("vanilla_proofs:finish");

        let sanity_check =
            S::verify_all_partitions(&pub_params.vanilla_params, pub_in, &vanilla_proofs)?;
        ensure!(sanity_check, "sanity check failed");

        info!("snark_proof:start");
        let groth_proofs = Self::circuit_proofs(
            pub_in,
            vanilla_proofs,
            &pub_params.vanilla_params,
            groth_params,
            pub_params.priority,
        )?;
        info!("snark_proof:finish");

        Ok(MultiProof::new(groth_proofs, &groth_params.pvk))
    }

    fn prove_with_vanilla<'b>(
        pub_params: &PublicParams<'a, S>,
        pub_in: &S::PublicInputs,
        vanilla_proofs: Vec<S::Proof>,
        groth_params: &'b groth16::MappedParameters<Bls12>,
    ) -> Result<MultiProof<'b>> {
        let partition_count = Self::partition_count(pub_params);

        // This will always run at least once, since there cannot be zero partitions.
        ensure!(partition_count > 0, "There must be partitions");

        info!("snark_proof:start");
        let groth_proofs = Self::circuit_proofs(
            pub_in,
            vanilla_proofs,
            &pub_params.vanilla_params,
            groth_params,
            pub_params.priority,
        )?;
        info!("snark_proof:finish");

        Ok(MultiProof::new(groth_proofs, &groth_params.pvk))
    }

    // verify is equivalent to ProofScheme::verify.
    fn verify<'b>(
        public_params: &PublicParams<'a, S>,
        public_inputs: &S::PublicInputs,
        multi_proof: &MultiProof<'b>,
        requirements: &S::Requirements,
    ) -> Result<bool> {
        ensure!(
            multi_proof.circuit_proofs.len() == Self::partition_count(public_params),
            "Inconsistent inputs"
        );

        let vanilla_public_params = &public_params.vanilla_params;
        let pvk = &multi_proof.verifying_key;

        if !<S as ProofScheme>::satisfies_requirements(
            &public_params.vanilla_params,
            requirements,
            multi_proof.circuit_proofs.len(),
        ) {
            return Ok(false);
        }

        let inputs: Vec<_> = (0..multi_proof.circuit_proofs.len())
            .into_par_iter()
            .map(|k| Self::generate_public_inputs(public_inputs, vanilla_public_params, Some(k)))
            .collect::<Result<_>>()?;

        let proofs: Vec<_> = multi_proof.circuit_proofs.iter().collect();
        let res = verify_proofs_batch(pvk, &mut OsRng, &proofs, &inputs)?;
        Ok(res)
    }

    /// Efficiently verify multiple proofs.
    fn batch_verify<'b>(
        public_params: &PublicParams<'a, S>,
        public_inputs: &[S::PublicInputs],
        multi_proofs: &[MultiProof<'b>],
        requirements: &S::Requirements,
    ) -> Result<bool> {
        ensure!(
            public_inputs.len() == multi_proofs.len(),
            "Inconsistent inputs"
        );
        for proof in multi_proofs {
            ensure!(
                proof.circuit_proofs.len() == Self::partition_count(public_params),
                "Inconsistent inputs"
            );
        }
        ensure!(!public_inputs.is_empty(), "Cannot verify empty proofs");

        let vanilla_public_params = &public_params.vanilla_params;
        // just use the first one, the must be equal any way
        let pvk = &multi_proofs[0].verifying_key;

        for multi_proof in multi_proofs.iter() {
            if !<S as ProofScheme>::satisfies_requirements(
                &public_params.vanilla_params,
                requirements,
                multi_proof.circuit_proofs.len(),
            ) {
                return Ok(false);
            }
        }

        let inputs: Vec<_> = multi_proofs
            .par_iter()
            .zip(public_inputs.par_iter())
            .flat_map(|(multi_proof, pub_inputs)| {
                (0..multi_proof.circuit_proofs.len())
                    .into_par_iter()
                    .map(|k| {
                        Self::generate_public_inputs(pub_inputs, vanilla_public_params, Some(k))
                    })
                    .collect::<Result<Vec<_>>>()
                    .expect("Invalid public inputs") // TODO: improve error handling
            })
            .collect::<Vec<_>>();
        let circuit_proofs: Vec<_> = multi_proofs
            .iter()
            .flat_map(|m| m.circuit_proofs.iter())
            .collect();

        let res = verify_proofs_batch(pvk, &mut OsRng, &circuit_proofs[..], &inputs)?;

        Ok(res)
    }


    fn write_to_file(deployment_file: impl AsRef<Path>, circuits: &Vec<C>, groth_params: &MappedParameters<Bls12>) {
        // println!("write_to_file: {:?}", &circuit_file.as_ref().display());
        // let file = std::fs::read(circuit_file).map_err(|_| GevulotError::ErrorIo)?;
        // println!("  read in {} bytes", file.len());
        // let r1cs = general_purpose::STANDARD_NO_PAD.encode(&file);

        // let created = SystemTime::now()
        //     .duration_since(UNIX_EPOCH)
        //     .unwrap()
        //     .as_millis() as u64;

        // let program_id = Uuid::new_v4();
        // println!("  program id: {:?}", program_id);
        // let program_path = format!("deployments/{program_id}.json");
        // println!("  program path: {}", program_path);
        // FilecoinDeployment
        // let tempo = json!(groth_params);
        let deployment = json!(FilecoinDeployment {
            circuits: "this is the circuits string".to_owned(),
            groth_params: "this is the groth params".to_owned() }).to_string();
        // let program = format!("this is it");
        println!("  deployment len: {}", deployment.len());
        std::fs::write(deployment_file, deployment).unwrap();
        // Ok(program_id.to_string())
    }

    /// circuit_proof creates and synthesizes a circuit from concrete params/inputs, then generates a
    /// groth proof from it. It returns a groth proof.
    /// circuit_proof is used internally and should neither be called nor implemented outside of
    /// default trait methods.
    fn circuit_proofs(
        pub_in: &S::PublicInputs,
        vanilla_proofs: Vec<S::Proof>,
        pub_params: &S::PublicParams,
        groth_params: &groth16::MappedParameters<Bls12>,
        priority: bool,
    ) -> Result<Vec<groth16::Proof<Bls12>>> {
        println!("asdf: circuit_proofs");
        let mut rng = OsRng;
        ensure!(
            !vanilla_proofs.is_empty(),
            "cannot create a circuit proof over missing vanilla proofs"
        );

        let circuits = vanilla_proofs
            .into_par_iter()
            .enumerate()
            .map(|(k, vanilla_proof)| {
                Self::circuit(
                    pub_in,
                    C::ComponentPrivateInputs::default(),
                    &vanilla_proof,
                    pub_params,
                    Some(k),
                )
            })
            .collect::<Result<Vec<_>>>()?;

        println!("asdf: groth params param_file_path {:?}", groth_params.param_file_path);
        println!("asdf: groth params params {:?}", groth_params.params);
        println!("asdf: groth params vk {:?}", groth_params.vk);
        // // println!("asdf: groth params pvk {:?}", groth_params.pvk);
        println!("asdf: groth params h {:?}", groth_params.h.len());
        println!("asdf: groth params l {:?}", groth_params.l.len());
        println!("asdf: groth params a {:?}", groth_params.a.len());
        println!("asdf: groth params b_g1 {:?}", groth_params.b_g1.len());
        println!("asdf: groth params b_g2 {:?}", groth_params.b_g2.len());
        println!("asdf: groth params h 0 {:?}", groth_params.h[0]);
        println!("asdf: groth params l 0 {:?}", groth_params.l[0]);
        println!("asdf: groth params a 0 {:?}", groth_params.a[0]);
        println!("asdf: groth params b_g1 0 {:?}", groth_params.b_g1[0]);
        println!("asdf: groth params b_g2 0 {:?}", groth_params.b_g2[0]);
        println!("asdf: groth params checked {:?}", groth_params.checked);
        println!("asdf: circuits len {:?}", circuits.len());

    // /// The parameter file we're reading from.
    // pub param_file_path: PathBuf,
    // /// The file descriptor we have mmaped.
    // pub param_file: File,
    // /// The actual mmap.
    // pub params: Mmap,

    // /// This is always loaded (i.e. not lazily loaded).
    // pub vk: VerifyingKey<E>,
    // pub pvk: PreparedVerifyingKey<E>,

    // /// Elements of the form ((tau^i * t(tau)) / delta) for i between 0 and
    // /// m-2 inclusive. Never contains points at infinity.
    // pub h: Vec<Range<usize>>,

    // /// Elements of the form (beta * u_i(tau) + alpha v_i(tau) + w_i(tau)) / delta
    // /// for all auxiliary inputs. Variables can never be unconstrained, so this
    // /// never contains points at infinity.
    // pub l: Vec<Range<usize>>,

    // /// QAP "A" polynomials evaluated at tau in the Lagrange basis. Never contains
    // /// points at infinity: polynomials that evaluate to zero are omitted from
    // /// the CRS and the prover can deterministically skip their evaluation.
    // pub a: Vec<Range<usize>>,

    // /// QAP "B" polynomials evaluated at tau in the Lagrange basis. Needed in
    // /// G1 and G2 for C/B queries, respectively. Never contains points at
    // /// infinity for the same reason as the "A" polynomials.
    // pub b_g1: Vec<Range<usize>>,
    // pub b_g2: Vec<Range<usize>>,

    // pub checked: bool,




        let groth_proofs = if priority {
            println!("asdf: go into bellperson land");
            Self::write_to_file("fc-groth16-test.json", &circuits, &groth_params);
            create_random_proof_batch_in_priority(circuits, groth_params, &mut rng)?
        } else {
            create_random_proof_batch(circuits, groth_params, &mut rng)?
        };
        println!("asdf: back from bellperson land");


        groth_proofs
            .into_iter()
            .map(|groth_proof| {
                let mut proof_vec = Vec::new();
                groth_proof.write(&mut proof_vec)?;
                let gp = groth16::Proof::<Bls12>::read(&proof_vec[..])?;
                Ok(gp)
            })
            .collect()
    }

    /// Given a prover_srs key, a list of groth16 proofs, and an ordered list of seeds
    /// (used to derive the PoRep challenges) hashed pair-wise with the comm_rs using sha256, aggregate them all into
    /// an AggregateProof type.
    fn aggregate_proofs(
        prover_srs: &ProverSRS<Bls12>,
        hashed_seeds_and_comm_rs: &[u8],
        proofs: &[groth16::Proof<Bls12>],
        version: groth16::aggregate::AggregateVersion,
    ) -> Result<AggregateProof<Bls12>> {
        Ok(aggregate_proofs::<Bls12>(
            prover_srs,
            hashed_seeds_and_comm_rs,
            proofs,
            version,
        )?)
    }

    /// Verifies the aggregate proof, with respect to the flattened input list.
    ///
    /// Note that this method internally instantiates an OSRng and passes it to the `verify_aggregate_proofs`
    /// method in bellperson.  While proofs would normally parameterize the type of rng used, we don't
    /// want it exposed past this level so as not to force the wrapper calls around this method in
    /// rust-filecoin-proofs-api to unroll this call outside of the tree parameterized `with_shape` macro
    /// usage.
    fn verify_aggregate_proofs(
        ip_verifier_srs: &VerifierSRS<Bls12>,
        pvk: &PreparedVerifyingKey<Bls12>,
        hashed_seeds_and_comm_rs: &[u8],
        public_inputs: &[Vec<Fr>],
        aggregate_proof: &groth16::aggregate::AggregateProof<Bls12>,
        version: groth16::aggregate::AggregateVersion,
    ) -> Result<bool> {
        let mut rng = OsRng;

        Ok(verify_aggregate_proof(
            ip_verifier_srs,
            pvk,
            &mut rng,
            public_inputs,
            aggregate_proof,
            hashed_seeds_and_comm_rs,
            version,
        )?)
    }

    /// generate_public_inputs generates public inputs suitable for use as input during verification
    /// of a proof generated from this CompoundProof's bellperson::Circuit (C). These inputs correspond
    /// to those allocated when C is synthesized.
    fn generate_public_inputs(
        pub_in: &S::PublicInputs,
        pub_params: &S::PublicParams,
        partition_k: Option<usize>,
    ) -> Result<Vec<Fr>>;

    /// circuit constructs an instance of this CompoundProof's bellperson::Circuit.
    /// circuit takes PublicInputs, PublicParams, and Proof from this CompoundProof's proof::ProofScheme (S)
    /// and uses them to initialize Circuit fields which will be used to construct public and private
    /// inputs during circuit synthesis.
    fn circuit(
        public_inputs: &S::PublicInputs,
        component_private_inputs: C::ComponentPrivateInputs,
        vanilla_proof: &S::Proof,
        public_param: &S::PublicParams,
        partition_k: Option<usize>,
    ) -> Result<C>;

    fn blank_circuit(public_params: &S::PublicParams) -> C;

    /// If the rng option argument is set, parameters will be
    /// generated using it.  This is used for testing only, or where
    /// parameters are otherwise unavailable (e.g. benches).  If rng
    /// is not set, an error will result if parameters are not
    /// present.
    fn groth_params<R: RngCore>(
        rng: Option<&mut R>,
        public_params: &S::PublicParams,
    ) -> Result<groth16::MappedParameters<Bls12>> {
        Self::get_groth_params(rng, Self::blank_circuit(public_params), public_params)
    }

    /// If the rng option argument is set, parameters will be
    /// generated using it.  This is used for testing only, or where
    /// parameters are otherwise unavailable (e.g. benches).  If rng
    /// is not set, an error will result if parameters are not
    /// present.
    fn verifying_key<R: RngCore>(
        rng: Option<&mut R>,
        public_params: &S::PublicParams,
    ) -> Result<groth16::VerifyingKey<Bls12>> {
        Self::get_verifying_key(rng, Self::blank_circuit(public_params), public_params)
    }

    /// If the rng option argument is set, parameters will be
    /// generated using it.  This is used for testing only, or where
    /// parameters are otherwise unavailable (e.g. benches).  If rng
    /// is not set, an error will result if parameters are not
    /// present.
    fn srs_key<R: RngCore>(
        rng: Option<&mut R>,
        public_params: &S::PublicParams,
        num_proofs_to_aggregate: usize,
    ) -> Result<ProverSRS<Bls12>> {
        let generic_srs = Self::get_inner_product(
            rng,
            Self::blank_circuit(public_params),
            public_params,
            num_proofs_to_aggregate,
        )?;

        let (prover_srs, _verifier_srs) = generic_srs.specialize(num_proofs_to_aggregate);

        Ok(prover_srs)
    }

    /// If the rng option argument is set, parameters will be
    /// generated using it.  This is used for testing only, or where
    /// parameters are otherwise unavailable (e.g. benches).  If rng
    /// is not set, an error will result if parameters are not
    /// present.
    fn srs_verifier_key<R: RngCore>(
        rng: Option<&mut R>,
        public_params: &S::PublicParams,
        num_proofs_to_aggregate: usize,
    ) -> Result<VerifierSRS<Bls12>> {
        let generic_srs = Self::get_inner_product(
            rng,
            Self::blank_circuit(public_params),
            public_params,
            num_proofs_to_aggregate,
        )?;

        let (_prover_srs, verifier_srs) = generic_srs.specialize(num_proofs_to_aggregate);

        Ok(verifier_srs)
    }

    fn circuit_for_test(
        public_parameters: &PublicParams<'a, S>,
        public_inputs: &S::PublicInputs,
        private_inputs: &S::PrivateInputs,
    ) -> Result<(C, Vec<Fr>)> {
        let vanilla_params = &public_parameters.vanilla_params;
        let partition_count = partition_count(public_parameters.partitions);
        let vanilla_proofs = S::prove_all_partitions(
            vanilla_params,
            public_inputs,
            private_inputs,
            partition_count,
        )
        .context("failed to generate partition proofs")?;

        ensure!(
            vanilla_proofs.len() == partition_count,
            "Vanilla proofs didn't match number of partitions."
        );

        let partitions_are_verified =
            S::verify_all_partitions(vanilla_params, public_inputs, &vanilla_proofs)
                .context("failed to verify partition proofs")?;

        ensure!(partitions_are_verified, "Vanilla proof didn't verify.");

        // Some(0) because we only return a circuit and inputs for the first partition.
        // It would be more thorough to return all, though just checking one is probably
        // fine for verifying circuit construction.
        let partition_pub_in = S::with_partition(public_inputs.clone(), Some(0));
        let inputs = Self::generate_public_inputs(&partition_pub_in, vanilla_params, Some(0))?;

        let circuit = Self::circuit(
            &partition_pub_in,
            C::ComponentPrivateInputs::default(),
            &vanilla_proofs[0],
            vanilla_params,
            Some(0),
        )?;

        Ok((circuit, inputs))
    }

    /// Like circuit_for_test but returns values for all partitions.
    fn circuit_for_test_all(
        public_parameters: &PublicParams<'a, S>,
        public_inputs: &S::PublicInputs,
        private_inputs: &S::PrivateInputs,
    ) -> Result<Vec<(C, Vec<Fr>)>> {
        let vanilla_params = &public_parameters.vanilla_params;
        let partition_count = partition_count(public_parameters.partitions);
        let vanilla_proofs = S::prove_all_partitions(
            vanilla_params,
            public_inputs,
            private_inputs,
            partition_count,
        )
        .context("failed to generate partition proofs")?;

        ensure!(
            vanilla_proofs.len() == partition_count,
            "Vanilla proofs didn't match number of partitions."
        );

        let partitions_are_verified =
            S::verify_all_partitions(vanilla_params, public_inputs, &vanilla_proofs)
                .context("failed to verify partition proofs")?;

        ensure!(partitions_are_verified, "Vanilla proof didn't verify.");

        let mut res = Vec::with_capacity(partition_count);
        for (partition, vanilla_proof) in vanilla_proofs.iter().enumerate() {
            let partition_pub_in = S::with_partition(public_inputs.clone(), Some(partition));
            let inputs =
                Self::generate_public_inputs(&partition_pub_in, vanilla_params, Some(partition))?;

            let circuit = Self::circuit(
                &partition_pub_in,
                C::ComponentPrivateInputs::default(),
                vanilla_proof,
                vanilla_params,
                Some(partition),
            )?;
            res.push((circuit, inputs));
        }
        Ok(res)
    }
}
