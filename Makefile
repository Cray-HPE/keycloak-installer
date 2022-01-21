#
# MIT License
#
# (C) Copyright 2019-2022 Hewlett Packard Enterprise Development LP
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# (MIT License)

# DOCKER
IMAGE_NAME ?= cray-keycloak-setup
IMAGE_VERSION ?= $(shell cat .version)
DOCKER_IMAGE ?= ${IMAGE_NAME}:${IMAGE_VERSION}

# HELM CHARTS
CHART_PATH ?= kubernetes
CHART_VERSION_1 ?= local
CHART_VERSION_2 ?= local
CHART_NAME_1 ?= "cray-keycloak"
CHART_NAME_1 ?= "cray-keycloak-users-localize"


charts: chart1 chart2

image:
	docker build --pull ${DOCKER_ARGS} --tag '${DOCKER_IMAGE}' .

test:
	mkdir -p results
	docker build --pull ${DOCKER_ARGS} --tag '${DOCKER_IMAGE}-codestyle' --target codestyle .
	docker run --rm '${DOCKER_IMAGE}-codestyle'
	docker build --pull ${DOCKER_ARGS} --tag '${DOCKER_IMAGE}-test' --target testing .
	docker run --rm --mount type=bind,source=$(PWD)/results,destination=/results '${DOCKER_IMAGE}-test'

chart1:
	echo "appVersion: ${IMAGE_VERSION}" >> ${CHART_PATH}/${CHART_NAME_1}/Chart.yaml
	helm dep up ${CHART_PATH}/${CHART_NAME_1}
	helm package ${CHART_PATH}/${CHART_NAME_1} -d ${CHART_PATH}/.packaged --version ${CHART_VERSION_1}

chart2:
	echo "appVersion: ${IMAGE_VERSION}" >> ${CHART_PATH}/${CHART_NAME_2}/Chart.yaml
	helm dep up ${CHART_PATH}/${CHART_NAME_2}
	helm package ${CHART_PATH}/${CHART_NAME_2} -d ${CHART_PATH}/.packaged --version ${CHART_VERSION_2}
