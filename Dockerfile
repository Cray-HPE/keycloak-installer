
FROM dtr.dev.cray.com/cache/alpine-python:2.7 as testing_base

WORKDIR /usr/src/app

COPY requirements.txt requirements_test.txt constraints.txt ./

RUN pip install --no-cache-dir -r requirements.txt && \
 pip install --no-cache-dir -r requirements_test.txt

COPY . .


FROM testing_base as testing

CMD [ "./docker_test_entry.sh" ]


FROM testing_base as codestyle

CMD [ "./docker_codestyle_entry.sh" ]


FROM dtr.dev.cray.com/cache/alpine-python:2.7

WORKDIR /usr/src/app

COPY requirements.txt constraints.txt ./

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "python", "keycloak_setup/keycloak_setup.py" ]
