
DOCKER:= @docker
IMAGE=custum-network-analysis
REGISTRY=registry.gitlab.com/maissacrement
VERSION=1.0.0

env ?= .env
-include $(env)
export $(shell sed 's/=.*//' $(env))

### CVE Analyser ###

run-project-analysis:
	@echo "On donne des droit a notre script d'analyse pour s'executer ..."
	@chmod +x ./scripts/sys/docker-compose-scan-analisis.sh
	@echo "Lancement ..."
	@./scripts/sys/docker-compose-scan-analisis.sh

running-container-analisis:
	@echo "On donne des droit a notre script d'analyse pour s'executer ..."
	@chmod +x ./scripts/sys/running-container-analisys.sh
	@echo "Lancement ..."
	@./scripts/sys/running-container-analisys.sh

### Execute workflow shell ###

workflow-attack-example:
	docker compose -f ./monitoring.yml -f ./docker-compose.yml -f ./nginx-workflow.yml up -d --build

deploy:
	ansible-playbook cd.yml
	
# You can put here ure workflow
# max-vuln-cve2025:

analysis: run-project-analysis running-container-analisis

login:
	${DOCKER} login registry.gitlab.com

version:
	@echo ${VERSION}

build:
	${DOCKER} build -t ${IMAGE}:${VERSION} ./custum-network-analysis -f ./docker/Dockerfile.exporter 

pull:
	${DOCKER} pull ${REGISTRY}/${IMAGE}:latest

dev:
	${DOCKER} run -it --rm \
	    -p ${PORT}:${PORT} \
	${IMAGE}:${VERSION}

tag:
	${DOCKER} tag ${IMAGE}:${VERSION} ${REGISTRY}/${IMAGE}:${VERSION}
	${DOCKER} tag ${IMAGE}:${VERSION} ${REGISTRY}/${IMAGE}:latest

push: login build tag
	${DOCKER} push ${REGISTRY}/${IMAGE}:${VERSION}
	${DOCKER} push ${REGISTRY}/${IMAGE}:latest

prod: 
	${DOCKER} pull ${REGISTRY}/${IMAGE}:latest
	${DOCKER} run -it --rm -p ${PORT}:${PORT} ${REGISTRY}/${IMAGE}:latest
