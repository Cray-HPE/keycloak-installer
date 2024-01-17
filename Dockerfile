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
ARG ALPINE_BASE_IMAGE=artifactory.algol60.net/csm-docker/stable/docker.io/library/alpine:3.18

FROM $ALPINE_BASE_IMAGE as testing_base

WORKDIR /usr/src/app

RUN apk add --no-cache python3 && \
    ln -sf python3 /usr/bin/python && \
    apk add --update --no-cache openssl

RUN python3 -m ensurepip
RUN pip3 install --no-cache --upgrade pip setuptools==65.5.1

COPY requirements.txt requirements_test.txt constraints.txt ./

RUN pip3 install --no-cache-dir -r requirements.txt && \
 pip3 install --no-cache-dir -r requirements_test.txt

COPY . .


FROM testing_base as testing

CMD [ "./docker_test_entry.sh" ]


FROM testing_base as codestyle

CMD [ "./docker_codestyle_entry.sh" ]


FROM $ALPINE_BASE_IMAGE

WORKDIR /usr/src/app

RUN apk add --no-cache python3 && \
    ln -sf python3 /usr/bin/python && \
    apk add --update --no-cache openssl

RUN python3 -m ensurepip
RUN pip3 install --no-cache --upgrade pip setuptools==65.5.1

COPY requirements.txt constraints.txt ./

RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

USER 65534:65534

CMD [ "python", "keycloak_setup/keycloak_setup.py" ]
