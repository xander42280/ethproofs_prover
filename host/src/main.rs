use common::file;
use ethers_providers::Middleware;
use ethers_providers::{Http, Provider};
use k256::elliptic_curve::rand_core::block;
use std::collections::BTreeMap;
use std::env;
use std::fs::read;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use std::time::UNIX_EPOCH;
use zkm_sdk::{prover::ClientCfg, prover::ProverInput, ProverClient};

mod ethproofs_client;

const VK_STR: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../vk.base64"));

async fn prove(
    cfg: &ClientCfg,
    json_path: &str,
    elf_path: &str,
    seg_size: u32,
    execute_only: bool,
    outdir: &str,
    block_no: u64,
) -> Option<(String, u64, u64)> {
    log::info!("Start prove block! block_no:{}", block_no);
    let prover_client = ProverClient::new(cfg).await;
    let input = ProverInput {
        elf: read(elf_path).unwrap(),
        public_inputstream: read(json_path).unwrap(),
        private_inputstream: vec![],
        seg_size,
        execute_only,
        ..Default::default()
    };

    let mut ret = None;
    let start = Instant::now();
    let proving_result = prover_client.prover.prove(&input, None).await;
    match proving_result {
        Ok(Some(prover_result)) => {
            if !execute_only {
                if prover_result.proof_with_public_inputs.is_empty() {
                    log::info!(
                        "Fail: snark_proof_with_public_inputs.len() is : {}.Please try setting SEG_SIZE={}",
                        prover_result.proof_with_public_inputs.len(), seg_size/2
                    );
                }
                let output_path = Path::new(outdir);
                let proof_result_path =
                    output_path.join(format!("{}_snark_proof_with_public_inputs.json", block_no));
                let mut f = file::new(&proof_result_path.to_string_lossy());
                match f.write(prover_result.proof_with_public_inputs.as_slice()) {
                    Ok(bytes_written) => {
                        log::info!("Proof: successfully written {} bytes.", bytes_written);
                        ret = Some((base64::encode(prover_result.proof_with_public_inputs), prover_result.total_steps, prover_result.split_cost));
                    }
                    Err(e) => {
                        log::info!("Proof: failed to write to file: {}", e);
                    }
                }
                log::info!("Generating proof successfully.");
            } else {
                log::info!("Generating proof successfully .The proof is not saved.");
            }
        }
        Ok(None) => {
            log::info!("Failed to generate proof.The result is None.");
        }
        Err(e) => {
            log::info!("Failed to generate proof. error: {}", e);
        }
    }

    let end = Instant::now();
    let elapsed = end.duration_since(start);
    log::info!(
        "Elapsed time: {:?} secs block_no:{}",
        elapsed.as_secs(),
        block_no
    );
    ret
}

#[allow(clippy::too_many_arguments)]
async fn prove_tx(
    cfg: &ClientCfg,
    outdir: &str,
    elf_path: &str,
    seg_size: u32,
    execute_only: bool,
    suite_path: &str,
    block_no: u64,
    ethproofs_client: &ethproofs_client::EthproofClient,
    cluster_id: i64,
    report: bool,
) -> anyhow::Result<()> {
    // let mut buf = Vec::new();
    // let json_string = serde_json::to_string(&test_suite).expect("Failed to serialize");
    // bincode::serialize_into(&mut buf, &json_string).expect("serialization failed");
    // bincode::serialize_into(&mut buf, &test_suite).expect("serialization failed");
    // log::debug!("test_suite len: {}", buf.len());
    // let suite_path = format!("{}/{}.bin", outdir, block_no);
    // std::fs::write(suite_path.clone(), &buf)?;
    let buf = std::fs::read(suite_path).unwrap();
    let test_suite = bincode::deserialize::<models::TestSuite>(&buf).unwrap();
    let check_start_time = Instant::now();
    match check::execute_test_suite_from_bytes(&buf) {
        Ok(_) => {}
        Err(e) => {
            log::error!("skip: {} check failed: {:?}", block_no, e);
            return Ok(());
        }
    }
    let check_end_time = Instant::now();
    log::info!(
        "Elapsed time: {:?} micros check block_no:{}",
        check_end_time.duration_since(check_start_time).as_micros(),
        block_no
    );
    if elf_path.is_empty() {
        log::info!("ELF_PATH is empty, skip proving");
        return Ok(());
    }
    let proof_id = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let req = ethproofs_client::QueuedProofRequest {
        block_number: block_no,
        cluster_id,
        proof_id,
    };
    log::info!("[queued_proof] req: {:?}", req);
    if report {
        match ethproofs_client.queued_proof(&req).await {
            Ok(res) => {
                log::info!("[queued_proof] res: {:?}", res);
            }
            Err(e) => {
                log::error!("[queued_proof] error: {:?}", e);
                return Err(e);
            }
        }
    }

    let req = ethproofs_client::ProvingProofRequest {
        block_number: block_no,
        cluster_id,
        proof_id,
    };
    log::info!("[proving_proof] req: {:?}", req);
    if report {
        match ethproofs_client.proving_proof(&req).await {
            Ok(res) => {
                log::info!("[proving_proof] res: {:?}", res);
            }
            Err(e) => {
                log::error!("[proving_proof] error: {:?}", e);
                return Err(e);
            }
        }
    }
    let start_time = Instant::now();
    let result = prove(
        cfg,
        &suite_path,
        elf_path,
        seg_size,
        execute_only,
        outdir,
        block_no,
    )
    .await;
    let end_time = Instant::now();
    log::info!(
        "Elapsed time: {};{};{};{}",
        block_no,
        test_suite.0.len(),
        test_suite
            .0
            .first_key_value()
            .unwrap()
            .1
            .env
            .parent_blob_gas_used
            .unwrap_or_default(),
        end_time.duration_since(start_time).as_secs(),
    );
    let proof = match result {
        Some(proof) => proof,
        None => ("".to_string(), 0, 0),
    };
    let req = ethproofs_client::ProvedProofRequest {
        block_number: block_no,
        cluster_id,
        proof_id,
        proving_cycles: proof.1,
        proving_time: end_time.duration_since(start_time).as_millis() as u64 - proof.2,
        proof: proof.0.clone(),
        verifier_id: VK_STR.to_string(),
        ..Default::default()
    };
    log::info!("[proved_proof] req: {:?}", req);
    if report {
        match ethproofs_client.proved_proof(&req).await {
            Ok(res) => {
                log::info!("[proved_proof] res: {:?}", res);
            }
            Err(e) => {
                log::error!("[proved_proof] error: {:?}", e);
            }
        }
    }
    Ok(())
}

async fn check(filepath: &str) -> anyhow::Result<()> {
    let buf = std::fs::read(filepath).expect("Failed to read file");
    check::execute_test_suite_from_bytes(&buf).unwrap();
    Ok(())
}

async fn create_cluster(ethproofs_client: &ethproofs_client::EthproofClient) {
    let req = ethproofs_client::CreateClusterRequest {
        nickname: "ZKM".to_string(),
        description: "zkm gpu prover".to_string(),
        hardware: "zkm gpu prover".to_string(),
        cycle_type: "mips".to_string(),
        proof_type: "Groth16".to_string(),
        configuration: vec![ethproofs_client::ClusterConfiguration {
            instance_type: "g5.8xlarge".to_string(),
            instance_count: 2,
        }],
    };
    log::info!("req: {:?}", req);
    match ethproofs_client.create_cluster(&req).await {
        Ok(res) => {
            log::info!("res: {:?}", res);
        }
        Err(e) => {
            log::error!("error: {:?}", e);
        }
    }
}

async fn create_single_machine(ethproofs_client: &ethproofs_client::EthproofClient) {
    let req = ethproofs_client::CreateSingleMachineRequest {
        nickname: "ZKM".to_string(),
        description: "zkm gpu prover".to_string(),
        hardware: "zkm gpu prover".to_string(),
        cycle_type: "mips".to_string(),
        proof_type: "Groth16".to_string(),
        instance_type: "p3.8xlarge".to_string(),
    };
    log::info!("req: {:?}", req);
    match ethproofs_client.single_machine(&req).await {
        Ok(res) => {
            log::info!("res: {:?}", res);
        }
        Err(e) => {
            log::error!("error: {:?}", e);
        }
    }
}

async fn generate_test_suite(client: Arc<Provider<Http>>, start_block_no: u64, chain_id: u64, outdir: &str) {
    let mut last_block_no = 0u64;
    let mut block_no = start_block_no;
    let mut retry_count = 0;
    loop {
        if block_no == last_block_no {
            if block_no > 0 {
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            }
            let latest_block_no_ret = get_prove_block_no(client.clone()).await;
            match latest_block_no_ret {
                Ok(latest_block_no) => {
                    if block_no == 0 {
                        block_no = latest_block_no;
                    } else {
                        if block_no + 100 <= latest_block_no {
                            block_no += 100;
                        }
                    }
                }
                Err(e) => {
                    log::error!("Failed to get latest block_no: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                }
            }
            continue;
        }

        log::info!("Generating json file for block_no: {} start", block_no);
        let test_suite = executor::process(client.clone(), block_no, chain_id).await;
        match test_suite {
            anyhow::Result::Ok(items) => {
                log::info!(
                    "Generating json file for block_no: {} is successful, txs: {}",
                    block_no,
                    items.0.len(),
                );
                let mut buf = Vec::new();
                bincode::serialize_into(&mut buf, &items).expect("serialization failed");
                log::debug!("test_suite len: {}", buf.len());
                let suite_path = format!("{}/{}.bin", outdir, block_no);
                std::fs::write(suite_path.clone(), &buf).unwrap();
                last_block_no = block_no;
                retry_count = 0;
            }
            Err(e) => {
                log::error!("Generating json file for block_no: {} is failed", block_no);
                log::error!("Error: {}", e);
                retry_count += 1;
                if retry_count > 5 {
                    let mut buf = Vec::new();
                    let items = models::TestSuite(BTreeMap::new());
                    bincode::serialize_into(&mut buf, &items).expect("serialization failed");
                    log::debug!("test_suite len: {}", buf.len());
                    let suite_path = format!("{}/{}.bin", outdir, block_no);
                    std::fs::write(suite_path.clone(), &buf).unwrap();
                    last_block_no = block_no;
                    retry_count = 0;
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }
        }
    }
}

async fn get_prove_block_no(client: Arc<Provider<Http>>) -> anyhow::Result<u64> {
    let block_no = client
        .get_block_number()
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    Ok(block_no.as_u64() / 100 * 100)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::try_init().unwrap_or_default();
    let block_no = env::var("BLOCK_NO").unwrap_or(String::from("1"));
    let mut block_no: u64 = block_no.parse().unwrap();
    let rpc_url = env::var("RPC_URL").unwrap_or(String::from("http://localhost:8545"));
    let chain_id = env::var("CHAIN_ID").unwrap_or(String::from("1"));
    let output_dir = env::var("OUTPUT_DIR").unwrap_or(String::from("./output"));
    let seg_size = env::var("SEG_SIZE").unwrap_or("65536".to_string());
    let seg_size = seg_size.parse::<_>().unwrap_or(65536);
    let execute_only = env::var("EXECUTE_ONLY").unwrap_or("false".to_string());
    let execute_only = execute_only.parse::<bool>().unwrap_or(false);
    let elf_path = env::var("ELF_PATH").unwrap_or("".to_string());
    let endpoint = env::var("ENDPOINT").ok();
    let ca_cert_path = env::var("CA_CERT_PATH").ok();
    let cert_path = env::var("CERT_PATH").ok();
    let key_path = env::var("KEY_PATH").ok();
    let domain_name = env::var("DOMAIN_NAME").ok();
    let private_key = env::var("PRIVATE_KEY").ok();
    let prove_loop = env::var("PROVE_LOOP").unwrap_or("false".to_string());
    let prove_loop = prove_loop.parse::<bool>().unwrap_or(false);
    let ethproofs_apikey = env::var("ETHPROOFS_APIKEY").unwrap_or("".to_string());
    let cluster_id = env::var("CLUSTER_ID").unwrap_or("1".to_string());
    let cluster_id = cluster_id.parse::<i64>().unwrap_or(1);
    let report = env::var("REPORT").unwrap_or("false".to_string());
    let report = report.parse::<bool>().unwrap_or(false);
    let max_tran_size = env::var("MAX_TRAN_SIZE").unwrap_or("150".to_string());
    let max_tran_size = max_tran_size.parse::<_>().unwrap_or(150);
    let ethproofs_client = ethproofs_client::EthproofClient::new(
        "https://ethproofs.org",
        &ethproofs_apikey,
    );

    let args: Vec<String> = env::args().collect();
    if args.len() > 2 {
        match args[1].as_str() {
            "check" => check(args[2].as_str()).await?,
            "create_cluster" => create_cluster(&ethproofs_client).await,
            "create_single_machine" => create_single_machine(&ethproofs_client).await,
            "generate_test_suite" => {
                let client = Provider::<Http>::try_from(rpc_url).unwrap();
                let client = Arc::new(client);
                generate_test_suite(client, block_no, chain_id.parse().unwrap(), &output_dir).await;
            }
            &_ => todo!(),
        };
        return Ok(());
    }

    let client = Provider::<Http>::try_from(rpc_url).unwrap();
    let client = Arc::new(client);

    let prover_cfg = ClientCfg {
        zkm_prover: env::var("ZKM_PROVER").unwrap_or(String::from("network")),
        vk_path: env::var("VK_PATH").unwrap_or(String::from("")),
        endpoint,
        ca_cert_path,
        cert_path,
        key_path,
        domain_name,
        private_key,
    };
    let mut last_block_no = 0u64;
    loop {
        if block_no == last_block_no {
            if block_no == 0 {
                block_no = get_prove_block_no(client.clone()).await?;
            } else {
                block_no += 100;
            }
            continue;
        }
        
        let file_path = format!("{}/{}.bin", output_dir, block_no);
        match std::fs::metadata(&file_path) {
            Ok(metadata) => {
                if metadata.is_file() {
                    log::info!("read {} success!", file_path);
                    let buf = std::fs::read(&file_path).unwrap();
                    let test_suite = bincode::deserialize::<models::TestSuite>(&buf);
                    if test_suite.is_err() {
                        log::warn!("Failed to deserialize test_suite: {:?}", test_suite);
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                        continue;
                    }
                    match test_suite {
                        Ok(test_suite) => {
                            if test_suite.0.len() > 0 && test_suite.0.len() < max_tran_size {
                                let _ = prove_tx(
                                    &prover_cfg,
                                    &output_dir,
                                    &elf_path,
                                    seg_size,
                                    execute_only,
                                    &file_path,
                                    block_no,
                                    &ethproofs_client,
                                    cluster_id,
                                    report,
                                )
                                .await;
                            }
                            last_block_no = block_no;
                        }
                        Err(e) => {
                            log::warn!("Failed to deserialize test_suite: {:?}", e);
                            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                            continue;
                        }  
                    }
                } else if metadata.is_dir() {
                    log::error!("The path: {} is a directory!", file_path);
                }
            }
            Err(_) => {
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            }
        }

        if !prove_loop {
            break;
        }
    }
    Ok(())
}
