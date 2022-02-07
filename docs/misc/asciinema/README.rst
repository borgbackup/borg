Do NOT run the examples without isolation (e.g docker) or 
this code may make undesirable changes to your host.

To this:
```sh
docker build --tag borg-examples .
asciinema rec -c 'docker run --rm borg-examples bash /asciinema/run-install.sh' --overwrite ./install.json
```
