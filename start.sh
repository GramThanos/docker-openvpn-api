#!/bin/bash

docker volume create --name ovpn_data
docker build -t docker-openvpn-api .
docker stop openvpn-api
docker rm openvpn-api
docker run -v ovpn_data:/etc/openvpn -d -p 1194:1194/udp -p 8080:8000 --name openvpn-api --cap-add=NET_ADMIN -e WEB_SECRET_TOKEN=example_web_secret docker-openvpn-api
