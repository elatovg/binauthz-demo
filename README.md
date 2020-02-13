# Hello App

This code supports [Implementing Binary Authorization with GKE and Cloud Build](https://cloud.google.com/solutions/binary-auth-with-cloud-build-and-gke)
published on cloud.google.com.

In this example the simple Go app is built using Cloud Build and deployed to Google
Kubernetes Engine (GKE). Attestations are made after the vulnerability scan completes.
The manifest templete in env demonstrates the break-glass process.

## Initial Setup
```bash
export COMPUTE_ZONE=us-east4-b
gcloud beta container clusters create binauthz \
    --machine-type "n1-standard-1" \
    --zone ${COMPUTE_ZONE}  \
    --num-nodes 2 \
    --enable-binauthz

export PROJECT_ID=$(gcloud info --format='value(config.project)')

export PROJECT_NUMBER="$(gcloud projects describe $PROJECT_ID \
    --format='get(projectNumber)')"
export CLOUD_BUILD_SA=$PROJECT_NUMBER@cloudbuild.gserviceaccount.com

gcloud projects add-iam-policy-binding ${PROJECT_ID} \
    --member=serviceAccount:${CLOUD_BUILD_SA} \
    --role=roles/container.developer
```

### Optional (if in cloud console)
```bash
sudo apt update
sudo apt install rng-tools
sudo rngd -s 512 -W 3600 -r /dev/urandom
# Gen GPG key for Vuln-Scanner
mkdir certs
gpg --full-generate-key

gpg --armor \
    --export vulnz_attestor@me.com > certs/vulnz_attestor.asc

gpg --export-secret-keys vulnz_attestor@me.com \
    > certs/vulnz_attestor.gpg

echo 'changeme!' > certs/vulnz_attestor.pass

gpg --list-secret-keys | grep -B1 vulnz_attestor | head -n 1 | awk \
    '{print $1}' > certs/vulnz_attestor.fpr

# store the keys in bucket
export BUCKET=${PROJECT_ID}-keys
gsutil mb -c regional -l us-east4 gs://$BUCKET
gsutil iam ch serviceAccount:$CLOUD_BUILD_SA:objectViewer \
    gs://$BUCKET

# create kms key ring
export KMS_KEYRING=binauthkeyring
export KMS_KEY=binauthkey

gcloud kms keyrings create $KMS_KEYRING --location us-east4
gcloud kms keys create $KMS_KEY \
    --location=us-east4 \
    --purpose=encryption \
    --keyring=$KMS_KEYRING

gcloud kms keys add-iam-policy-binding $KMS_KEY \
--keyring $KMS_KEYRING \
--location us-east4 \
--member=serviceAccount:$CLOUD_BUILD_SA \
--role='roles/cloudkms.cryptoKeyDecrypter'

gcloud kms encrypt \
    --plaintext-file certs/vulnz_attestor.gpg \
    --ciphertext-file certs/vulnz_attestor.gpg.enc \
    --key=$KMS_KEY \
    --keyring=$KMS_KEYRING \
    --location=us-east4

gcloud kms encrypt \
    --plaintext-file certs/vulnz_attestor.pass \
    --ciphertext-file certs/vulnz_attestor.pass.enc \
    --key=$KMS_KEY --keyring=$KMS_KEYRING --location=us-east4

gsutil cp certs/*.enc gs://$BUCKET/
gsutil cp certs/*.fpr gs://$BUCKET/
gsutil cp certs/*.asc gs://$BUCKET/
```

### Create the attestation

```bash
cat > /tmp/vulnz_note_payload.json << EOM
{
  "name": "projects/${PROJECT_ID}/notes/vulnz_attestor",
  "attestation_authority": {
    "hint": {
      "human_readable_name": "${PROJECT_ID}-vulnz_attestor"
    }
  }
}
EOM

curl -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $(gcloud auth print-access-token)"  \
    --data-binary @vulnz_note_payload.json  \
    "https://containeranalysis.googleapis.com/v1beta1/projects/${PROJECT_ID}/notes/?noteId=vulnz_attestor"

cat > vulnz_iam_request.json << EOM
{
  'resource': 'projects/${PROJECT_ID}/notes/vulnz_attestor',
  'policy': {
    'bindings': [
      {
        'role': 'roles/containeranalysis.notes.occurrences.viewer',
        'members': [
          'serviceAccount:${CLOUD_BUILD_SA}'
        ]
      },
      {
        'role': 'roles/containeranalysis.notes.attacher',
        'members': [
          'serviceAccount:${CLOUD_BUILD_SA}'
        ]
      }
    ]
  }
}
EOM

curl -X POST  \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $(gcloud auth print-access-token)" \
    --data-binary @vulnz_iam_request.json \
     "https://containeranalysis.googleapis.com/v1beta1/projects/${PROJECT_ID}/notes/vulnz_attestor:setIamPolicy"

gcloud --project="${PROJECT_ID}" \
    beta container binauthz attestors create "vulnz_attestor" \
    --attestation-authority-note="vulnz_attestor" \
    --attestation-authority-note-project="${PROJECT_ID}"

gcloud --project="${PROJECT_ID}" \
    beta container binauthz attestors public-keys add \
    --attestor="vulnz_attestor" \
    --public-key-file certs/vulnz_attestor.asc

# allow cloud build to verify attestation made by the vulnz-attestor

gcloud beta container binauthz attestors add-iam-policy-binding \
    "projects/${PROJECT_ID}/attestors/vulnz_attestor" \
    --member="serviceAccount:${CLOUD_BUILD_SA}" \
    --role=roles/binaryauthorization.attestorsVerifier

## create a binauthz policy

cat > binauth_policy.yaml << EOM
defaultAdmissionRule:
  enforcementMode: ENFORCED_BLOCK_AND_AUDIT_LOG
  evaluationMode: ALWAYS_DENY
globalPolicyEvaluationMode: ENABLE
clusterAdmissionRules:
  ${COMPUTE_ZONE}.binauthz:
    evaluationMode: REQUIRE_ATTESTATION
    enforcementMode: ENFORCED_BLOCK_AND_AUDIT_LOG
    requireAttestationsBy:
    - projects/${PROJECT_ID}/attestors/vulnz_attestor
EOM

gcloud beta container binauthz policy import binauth_policy.yaml

### create the scanner
git clone https://github.com/GoogleCloudPlatform/gke-binary-auth-tools \
    binauthz_tools

# build and push container to local reg
cd binauthz_tools
docker build -t gcr.io/${PROJECT_ID}/cloudbuild-attestor .

gcloud docker \
    -- push gcr.io/${PROJECT_ID}/cloudbuild-attestor

## create source code repo 
cd ..
gcloud source repos create binauthz-test
gcloud source repos clone binauthz-test
cp -R binauthz_tools/examples/hello-app/* binauthz-test/. 

# check the changes
git add -A && git commit \
    -m "commit (`date`)" && git push origin master

# break it on purpose
sed -i "s/FROM gcr\.io\/distroless\/static/FROM debian/g" Dockerfile
sed -i "s/Hello World/Binary Authorization/g" main.go
git commit -a -m "commit (`date`)" \
    && git push origin master
```

### check build
```bash
# apply manually
PROJECT_ID=$(gcloud info --format='value(config.project)')
TAG=$(gcloud container images list-tags gcr.io/${PROJECT_ID}/hello-app --limit 1 --format "value(tags)")
DIGEST=$(gcloud container images describe --format 'value(image_summary.digest)' gcr.io/$PROJECT_ID/hello-app:$TAG)

sed "s/GOOGLE_CLOUD_PROJECT/${PROJECT_ID}/g" \
    kubernetes/deployment.yaml.tpl | sed -e \
    "s/DIGEST/${DIGEST}/g" | kubectl apply -f -
```

### check failed deployment
```bash
k get events
```

### break glass

```bash
sed "s/GOOGLE_CLOUD_PROJECT/${PROJECT_ID}/g" \
    kubernetes/deployment.yaml.tpl | sed -e \
    "s/DIGEST/${DIGEST}/g"  | sed '31s/^#//' \
    | kubectl apply -f -

### fix it
TODO
```
