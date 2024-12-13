use anyhow::Ok;
use anyhow::Result;
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct ClusterConfiguration {
    pub instance_type: String,
    pub instance_count: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateSingleMachineRequest {
    pub nickname: String,
    pub description: String,
    pub hardware: String,
    pub cycle_type: String,
    pub proof_type: String,
    pub instance_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateSingleMachineResponse {
    pub id: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateClusterRequest {
    pub nickname: String,
    pub description: String,
    pub hardware: String,
    pub cycle_type: String,
    pub proof_type: String,
    pub configuration: Vec<ClusterConfiguration>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateClusterResponse {
    pub id: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct QueuedProofRequest {
    pub proof_id: i64,
    pub block_number: u64,
    pub cluster_id: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct QueuedProofResponse {
    pub proof_id: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProvingProofRequest {
    pub proof_id: i64,
    pub block_number: u64,
    pub cluster_id: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProvingProofResponse {
    pub proof_id: i64,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct ProvedProofRequest {
    pub proof_id: i64,
    pub block_number: u64,
    pub cluster_id: i64,
    // Milliseconds taken to generate the proof
    pub proving_time: u64,
    pub proving_cycles: u64,
    pub proof: String,
    pub verifier_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProvedProofResponse {
    pub proof_id: i64,
}

pub struct EthproofClient {
    client: Client,
    apikey: String,
    uri: String,
}

impl EthproofClient {
    pub fn new(uri: &str, apikey: &str) -> Self {
        Self {
            client: Client::new(),
            apikey: apikey.to_string(),
            uri: uri.to_string(),
        }
    }

    // https://staging--ethproofs.netlify.app/api/v0/clusters
    pub async fn create_cluster(
        &self,
        req: &CreateClusterRequest,
    ) -> Result<CreateClusterResponse> {
        self.post_json("api/v0/clusters", req).await
    }

    // https://staging--ethproofs.netlify.app/api/v0/single-machine
    pub async fn single_machine(
        &self,
        req: &CreateSingleMachineRequest,
    ) -> Result<CreateSingleMachineResponse> {
        self.post_json("api/v0/single-machine", req).await
    }

    // https://staging--ethproofs.netlify.app/api/v0/proofs/queued
    pub async fn queued_proof(&self, req: &QueuedProofRequest) -> Result<QueuedProofResponse> {
        self.post_json("api/v0/proofs/queued", req).await
    }

    // https://staging--ethproofs.netlify.app/api/v0/proofs/proving
    pub async fn proving_proof(&self, req: &ProvingProofRequest) -> Result<ProvingProofResponse> {
        self.post_json("api/v0/proofs/proving", req).await
    }

    // https://staging--ethproofs.netlify.app/api/v0/proofs/proved
    pub async fn proved_proof(&self, req: &ProvedProofRequest) -> Result<ProvedProofResponse> {
        self.post_json("api/v0/proofs/proved", req).await
    }

    pub async fn post_json<REQ: Serialize + Send + 'static, RES: DeserializeOwned + 'static>(
        &self,
        path: &str,
        req: &REQ,
    ) -> Result<RES> {
        let url = format!("{}/{}", self.uri, path);
        let params = serde_json::to_string(req)?;
        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.apikey))
            .header("Content-Type", "application/json")
            .body(params)
            .send()
            .await?;
        let res: RES = response.json().await?;
        Ok(res)
    }
}
