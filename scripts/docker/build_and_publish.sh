#!/bin/bash -eux

echo "Building docker image for borg version ${TAG}..."

vagrant scp stretch64:/vagrant/borg/borg.exe borg-linux64
docker build --pull -t borgbackup/borg:${TAG} .
docker tag borgbackup/borg:${TAG} borgbackup/borg:latest

echo "Running smoke test..."
docker run borgbackup/borg --version

echo "Login and publishing the docker image..."
docker login
docker push borgbackup/borg:${TAG}
docker push borgbackup/borg:latest
