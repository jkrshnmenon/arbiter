PWD ?= pwd_unknown
NS ?= 4rbit3r
IMAGE_NAME ?= $(notdir $(PWD))
TAG ?= latest
CONTAINER_NAME ?= default_instance

.PHONY: help build release shell exec commit run

help:
	@echo ''
	@echo 'Usage: make [TARGET] [EXTRA_ARGUMENTS]'
	@echo 'Targets:'
	@echo '  build    	build docker image $(NS)/$(IMAGE_NAME):$(TAG)'
	@echo '  release	push docker image $(NS)/$(IMAGE_NAME):$(TAG)'
	@echo '  shell		debug docker container for image $(NS)/$(IMAGE_NAME):$(TAG) as $(CONTAINER_NAME)'
	@echo '  exec		run docker container for image $(NS)/$(IMAGE_NAME):$(TAG) as $(CONTAINER_NAME)'
	@echo '  commit	build and push docker image $(NS)/$(IMAGE_NAME):$(TAG)'
	@echo '  run		build and run docker image $(NS)/$(IMAGE_NAME):$(TAG) as $(CONTAINER_NAME)'
	@echo ''
	@echo 'Extra arguments:'
	@echo 'TAG=:		make TAG="<tag>" (defaults to latest)'
	@echo 'IMAGE_NAME=:	make IMAGE_NAME="<image_name>" (defaults to directory name)'
	@echo 'CONTAINER_NAME=:make CONTAINER_NAME="<container_name>" (defaults to "default_instance")'


build:
	# test_scripts/update_image.sh $(TAG)
	docker build -t $(NS)/$(IMAGE_NAME):$(TAG) .

release: 
	docker push $(NS)/$(IMAGE_NAME):$(TAG)

shell: build
	docker run --rm --name $(CONTAINER_NAME) -it $(NS)/$(IMAGE_NAME):$(TAG) /bin/bash

debug: build
	docker run --rm -v $(PWD)/arbiter:/home/test/arbiter -v $(PWD)/dataset:/home/test/dataset --name $(CONTAINER_NAME) -it $(NS)/$(IMAGE_NAME):$(TAG) /bin/bash

exec:
	docker run --rm --name $(CONTAINER_NAME) -it $(NS)/$(IMAGE_NAME):$(TAG)

commit: build release

run: build shell

	
