use anyhow::{ensure, Context, Result};
use filecoin_hashers::Hasher;
use log::info;
use merkletree::merkle::MerkleTree;

use merkletree::hash::{Algorithm, Hashable};
use merkletree::merkle::Element;
use merkletree::store::{DiskStore, LevelCacheStore, Store, StoreConfig};
use typenum::Unsigned;

use storage_proofs_core::{
    compound_proof::{self, CompoundProof},
    merkle::MerkleTreeTrait,
    multi_proof::MultiProof,
    sector::SectorId,
};
use storage_proofs_post::fallback::{
    self, generate_sector_challenges, FallbackPoSt, FallbackPoStCompound, PrivateSector,
    PublicSector,
};

use serde_json::json;

use crate::{
    api::{as_safe_commitment, partition_vanilla_proofs},
    caches::{get_post_params, get_post_verifying_key},
    parameters::winning_post_setup_params,
    types::{
        ChallengeSeed, Commitment, FallbackPoStSectorProof, PoStConfig, PrivateReplicaInfo,
        ProverId, PublicReplicaInfo, SnarkProof,
    },
    PoStType,
};

/// Utilities
pub fn serialize_tree<E: Element, A: Algorithm<E>, S: Store<E>, U: Unsigned>(
    tree: MerkleTree<E, A, S, U>,
) -> Vec<u8> {
    let data = tree.data().expect("can't get tree's data [serialize_tree]");
    let data: Vec<E> = data
        .read_range(0..data.len())
        .expect("can't read actual data [serialize_tree]");
    let mut serialized_tree = vec![0u8; E::byte_len() * data.len()];
    let mut start = 0;
    let mut end = E::byte_len();
    for element in data {
        element.copy_to_slice(&mut serialized_tree[start..end]);
        start += E::byte_len();
        end += E::byte_len();
    }
    serialized_tree
}

/// Generates a Winning proof-of-spacetime with provided vanilla proofs.
pub fn generate_winning_post_with_vanilla<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
    vanilla_proofs: Vec<FallbackPoStSectorProof<Tree>>,
) -> Result<SnarkProof> {
    info!("generate_winning_post_with_vanilla:start");
    ensure!(
        post_config.typ == PoStType::Winning,
        "invalid post config type"
    );

    ensure!(
        vanilla_proofs.len() == post_config.sector_count,
        "invalid amount of vanilla proofs"
    );

    let randomness_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = winning_post_setup_params(post_config)?;

    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: None,
        priority: post_config.priority,
    };
    let pub_params: compound_proof::PublicParams<'_, FallbackPoSt<'_, Tree>> =
        FallbackPoStCompound::setup(&setup_params)?;
    let groth_params = get_post_params::<Tree>(post_config)?;

    let mut pub_sectors = Vec::with_capacity(vanilla_proofs.len());
    for vanilla_proof in &vanilla_proofs {
        pub_sectors.push(PublicSector {
            id: vanilla_proof.sector_id,
            comm_r: vanilla_proof.comm_r,
        });
    }

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: pub_sectors,
        k: None,
    };

    let partitions = pub_params.partitions.unwrap_or(1);
    let partitioned_proofs = partition_vanilla_proofs(
        post_config,
        &pub_params.vanilla_params,
        &pub_inputs,
        partitions,
        &vanilla_proofs,
    )?;

    let proof = FallbackPoStCompound::prove_with_vanilla(
        &pub_params,
        &pub_inputs,
        partitioned_proofs,
        &groth_params,
    )?;
    let proof = proof.to_vec()?;

    info!("generate_winning_post_with_vanilla:finish");

    Ok(proof)
}



/// Generates a Winning proof-of-spacetime.
pub fn generate_winning_post<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &[(SectorId, PrivateReplicaInfo<Tree>)],
    prover_id: ProverId,
) -> Result<SnarkProof> {
    info!("generate_winning_post:start");
    ensure!(
        post_config.typ == PoStType::Winning,
        "invalid post config type"
    );

    ensure!(
        replicas.len() == post_config.sector_count,
        "invalid amount of replicas"
    );

    let randomness_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = winning_post_setup_params(post_config)?;
    let param_sector_count = vanilla_params.sector_count;

    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: None,
        priority: post_config.priority,
    };
    let pub_params: compound_proof::PublicParams<'_, FallbackPoSt<'_, Tree>> =
        FallbackPoStCompound::setup(&setup_params)?;

    let jpost_config = json!(&post_config).to_string();
    info!("momo:  jpost_config {:?}", &jpost_config);
    info!("momo:  replicas {:?}", replicas);


    let groth_params = get_post_params::<Tree>(post_config)?;


    let trees = replicas
        .iter()
        .map(|(sector_id, replica)| {
            replica
                .merkle_tree(post_config.sector_size)
                .with_context(|| {
                    format!("generate_winning_post: merkle_tree failed: {:?}", sector_id)
                })
        })
        .collect::<Result<Vec<_>>>()?;
    // info!("\n\n\nmomo: trees len {}", trees.len());

    let mut pub_sectors = Vec::with_capacity(param_sector_count);
    let mut priv_sectors = Vec::with_capacity(param_sector_count);

    // println!("momo: param_sector_count {}", param_sector_count);
    for _ in 0..param_sector_count {
        for ((sector_id, replica), tree) in replicas.iter().zip(trees.iter()) {
            let comm_r = replica.safe_comm_r().with_context(|| {
                format!("generate_winning_post: safe_comm_r failed: {:?}", sector_id)
            })?;
            let comm_c = replica.safe_comm_c();
            let comm_r_last = replica.safe_comm_r_last();
            let jcomm_c = json!(&comm_c).to_string();
            // info!("momo:  jcomm_c {:?}", &jcomm_c);
            let jcomm_r_last = json!(&comm_r_last).to_string();
            // info!("momo:  jcomm_r_last {:?}", &jcomm_r_last);
            // let serialize_tree = serialize_tree(tree.inner);


            pub_sectors.push(PublicSector::<<Tree::Hasher as Hasher>::Domain> {
                id: *sector_id,
                comm_r,
            });
            priv_sectors.push(PrivateSector {
                tree,
                comm_c,
                comm_r_last,
            });
        }
    }

    // let tree = priv_sectors[0].tree;
    // let data = tree.data().expect("can't get tree's data [serialize_tree]");
    // println!("momo:  data  {:?}", data);
    // println!("momo:  leafs {:?}", tree.leafs());
    // println!("momo:  root {:?}", tree.root());
    // println!("momo:  len {:?}", tree.len());
    // println!("momo:  row_count {:?}", tree.row_count());
    // let data: Vec<Element> = data
    //     .read_range(0..data.len())
    //     .expect("can't read actual data [serialize_tree]");
    // let mut serialized_tree = vec![0u8; Element::byte_len() * data.len()];
    // let mut start = 0;
    // let mut end = Element::byte_len();
    // for element in data {
    //     element.copy_to_slice(&mut serialized_tree[start..end]);
    //     start += Element::byte_len();
    //     end += Element::byte_len();
    // }
    // println!("momo:  serialized tree len {}", serialized_tree.len());
    // serialized_tree



    let pub_inputs = fallback::PublicInputs::<<Tree::Hasher as Hasher>::Domain> {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: pub_sectors,
        k: None,
    };

    let priv_inputs = fallback::PrivateInputs::<Tree> {
        sectors: &priv_sectors,
    };

    // info!("asdf:  winning post, generate_winning_post");
    // info!("asdf:  pub_params {:?}", &pub_params);
    // info!("asdf:  pub_inputs {:?}", &pub_inputs);
    info!("\n\n\nmomo:  priv_inputs {:?}\n\n\n", &priv_inputs);
    // println!("asdf:  groth_params {:?}", &groth_params);

    let jpubparams = json!(&pub_params).to_string();
    let jpubinputs = json!(&pub_inputs).to_string();
    info!("oranj:  pub_params json {:?}", &jpubparams);
    info!("oranj:  pub_inputs json {:?}", &jpubinputs);

    // let jprivinputs = json!(&priv_inputs).to_string();
    // println!("asdf:  priv_inputs json {:?}", &jprivinputs);

    let proof =
        FallbackPoStCompound::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs, &groth_params)?;
    let proof = proof.to_vec()?;

    info!("generate_winning_post:finish");

    Ok(proof)
}

/// Given some randomness and the length of available sectors, generates the challenged sector.
///
/// The returned values are indices in the range of `0..sector_set_size`, requiring the caller
/// to match the index to the correct sector.
pub fn generate_winning_post_sector_challenge<Tree: MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    sector_set_size: u64,
    prover_id: Commitment,
) -> Result<Vec<u64>> {
    info!("generate_winning_post_sector_challenge:start");
    ensure!(sector_set_size != 0, "empty sector set is invalid");
    ensure!(
        post_config.typ == PoStType::Winning,
        "invalid post config type"
    );

    let prover_id_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(&prover_id, "prover_id")?;

    let randomness_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(randomness, "randomness")?;
    let result = generate_sector_challenges(
        randomness_safe,
        post_config.sector_count,
        sector_set_size,
        prover_id_safe,
    );

    info!("generate_winning_post_sector_challenge:finish");

    result
}

/// Verifies a winning proof-of-spacetime.
///
/// The provided `replicas` must be the same ones as passed to `generate_winning_post`, and be based on
/// the indices generated by `generate_winning_post_sector_challenge`. It is the responsibility of the
/// caller to ensure this.
pub fn verify_winning_post<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &[(SectorId, PublicReplicaInfo)],
    prover_id: ProverId,
    proof: &[u8],
) -> Result<bool> {
    info!("verify_winning_post:start");

    ensure!(
        post_config.typ == PoStType::Winning,
        "invalid post config type"
    );
    ensure!(
        post_config.sector_count == replicas.len(),
        "invalid amount of replicas provided"
    );

    let randomness_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = winning_post_setup_params(post_config)?;
    let param_sector_count = vanilla_params.sector_count;

    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: None,
        priority: false,
    };
    let pub_params: compound_proof::PublicParams<'_, FallbackPoSt<'_, Tree>> =
        FallbackPoStCompound::setup(&setup_params)?;

    let mut pub_sectors = Vec::with_capacity(param_sector_count);
    for _ in 0..param_sector_count {
        for (sector_id, replica) in replicas.iter() {
            let comm_r = replica.safe_comm_r().with_context(|| {
                format!("verify_winning_post: safe_comm_r failed: {:?}", sector_id)
            })?;
            pub_sectors.push(PublicSector {
                id: *sector_id,
                comm_r,
            });
        }
    }

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: pub_sectors,
        k: None,
    };

    let is_valid = {
        let verifying_key = get_post_verifying_key::<Tree>(post_config)?;

        let single_proof = MultiProof::new_from_reader(None, proof, &verifying_key)?;
        if single_proof.len() != 1 {
            return Ok(false);
        }

        FallbackPoStCompound::verify(
            &pub_params,
            &pub_inputs,
            &single_proof,
            &fallback::ChallengeRequirements {
                minimum_challenge_count: post_config.challenge_count * post_config.sector_count,
            },
        )?
    };

    if !is_valid {
        return Ok(false);
    }

    info!("verify_winning_post:finish");

    Ok(true)
}
