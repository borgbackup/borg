FROM debian:stretch

ENV LANG=C.UTF-8

COPY ./borg-linux64 /usr/bin/borg
COPY ./scripts/docker/borgbackup /usr/bin/
COPY ./scripts/docker/borgserver /usr/bin/

ENTRYPOINT ["/usr/bin/borg"]
