# Copyright 2019-2021 Hewlett Packard Enterprise Development LP

FROM arti.dev.cray.com/baseos-docker-master-local/alpine:3.13.5 as testing_base

WORKDIR /usr/src/app

RUN apk add --no-cache python3 && ln -sf python3 /usr/bin/python
RUN python3 -m ensurepip
RUN pip3 install --no-cache --upgrade pip setuptools==57.1.0

COPY requirements.txt requirements_test.txt constraints.txt ./

RUN pip3 install --no-cache-dir -r requirements.txt && \
 pip3 install --no-cache-dir -r requirements_test.txt

COPY . .


FROM testing_base as testing

CMD [ "./docker_test_entry.sh" ]


FROM testing_base as codestyle

CMD [ "./docker_codestyle_entry.sh" ]


FROM arti.dev.cray.com/baseos-docker-master-local/alpine:3.13.5

WORKDIR /usr/src/app

RUN apk add --no-cache python3 && ln -sf python3 /usr/bin/python
RUN python3 -m ensurepip
RUN pip3 install --no-cache --upgrade pip setuptools==57.1.0

COPY requirements.txt constraints.txt ./

RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

USER 65534:65534

CMD [ "python", "keycloak_setup/keycloak_setup.py" ]
