# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Make will use bash instead of sh
SHELL := /usr/bin/env bash
PROJECT_ID := $(shell gcloud config list --format "value(core.project)")
CLEAN_TAG := $(shell gcloud container images list-tags gcr.io/$(PROJECT_ID)/hello-app --format 'value(tags)' | tail -1)
CLEAN_IMG := $(shell gcloud container images describe --format 'value(image_summary.fully_qualified_digest)' gcr.io/$(PROJECT_ID)/hello-app:$(CLEAN_TAG))

SVC := $(shell kubectl get svc hello-app-service -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

check-current:
	gcloud config configurations activate ${PROJECT_ID}
	gcloud container images list-tags gcr.io/$(PROJECT_ID)/hello-app && echo -e "====\n"
	gcloud beta container images describe ${CLEAN_IMG} --show-package-vulnerability --format json | jq '.package_vulnerability_summary' && echo -e "====\n"
	gcloud beta container binauthz attestations list --artifact-url ${CLEAN_IMG} --attestor vulnz_attestor --format json | jq '.[0].noteName' && echo -e "====\n"
	gcloud beta container binauthz attestors list --format json | jq '.[0] | {name: .name, note: .userOwnedDrydockNote.noteReference}' && echo -e "====\n"
	kubectl get deploy hello-app && echo -e "====\n"
	kubectl get deploy hello-app -o jsonpath='{.spec.template.spec.containers[*].image}' && echo -e "====\n"
	curl http://${SVC} && echo -e "\n"

submit-vuln:
	gsed -i \
	"s/FROM gcr\.io\/distroless\/static/FROM debian/g" Dockerfile
	gsed -i \
	"s/Hello World/Binary Authorization/g" main.go
	git commit -a \
	-m "add vulnerability (`date`)" && git push origin master


LATEST_TAG := $(shell gcloud container images list-tags gcr.io/$(PROJECT_ID)/hello-app --format 'value(tags)' --limit 1)
LATEST_IMG := $(shell gcloud container images describe --format 'value(image_summary.fully_qualified_digest)' gcr.io/$(PROJECT_ID)/hello-app:$(LATEST_TAG))
CLEAN_DIGEST := $(shell gcloud container images describe --format 'value(image_summary.digest)' gcr.io/$(PROJECT_ID)/hello-app:$(CLEAN_TAG))
LATEST_DIGEST := $(shell gcloud container images describe --format 'value(image_summary.digest)' gcr.io/$(PROJECT_ID)/hello-app:$(LATEST_TAG))

check-last:
	gcloud config configurations activate ${PROJECT_ID}
	gcloud container images list-tags gcr.io/$(PROJECT_ID)/hello-app && echo -e "====\n"
	gcloud beta container images describe ${LATEST_IMG} --show-package-vulnerability --format json | jq '.package_vulnerability_summary.total_vulnerability_found' && echo -e "====\n"
	gcloud beta container binauthz attestations list --artifact-url ${LATEST_IMG} --attestor vulnz_attestor --format json 

deploy-vuln:
	gsed "s/GOOGLE_CLOUD_PROJECT/${PROJECT_ID}/g" \
    kubernetes/deployment.yaml.tpl | sed -e \
    "s/DIGEST/${LATEST_DIGEST}/g" | kubectl apply -f -
	sleep 5
	kubectl get events --sort-by='{.lastTimestamp}' | tail -1

revert-vuln:
	gsed -i \
	"s/FROM debian/FROM gcr\.io\/distroless\/static/g" Dockerfile
	gsed -i \
	"s/Binary Authorization/Hello World/g" main.go
	git commit -a -m \
	"remove vulnerability (`date`)" && git push origin master
