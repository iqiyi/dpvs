#!/bin/bash
#

openssl genrsa -out key.pem 2048
openssl req -new -key key.pem -out req.csr -config san.conf
openssl x509 -req -days 3650 -in req.csr -signkey key.pem -out cert.pem -extensions req_ext -extfile san.conf
