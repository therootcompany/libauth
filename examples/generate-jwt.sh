#!/bin/bash

keypairs sign \
    --exp 87660h \
    ./examples/privkey.ec.jwk.json \
    '{
        "iss": "https://therootcompany.github.io/libauth/",
        "sub": "1",
        "email_verified": false,
        "email": "jo@example.com"
    }' \
    > ./examples/jwt.txt \
    2> ./examples/jws.json
