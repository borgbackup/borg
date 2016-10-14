#BorgBackup
![GitHub Logo](https://borgbackup.readthedocs.io/en/stable/_static/logo.png)

1. [Documentation](https://borgbackup.readthedocs.io/en/stable/index.html)
2. [Original Project](https://github.com/borgbackup/borg)

##Descrição do Projeto

O Borg foi criado em maio de 2015 tendo sido “forked” de um projeto já existente denominado Attic, a razão desta decisão prende-se com a dificuldade de incorporar grandes modificações no Attic, desta forma o borg tenta estabelecer uma comunidade de desenvolvedores maior e mais aberta.
O principal objetivo deste software é disponibilizar uma forma segura e eficiente de fazer “backups”, usando um algoritmo de deduplicação adequado à realização de “backups” diários uma vez que apenas as alterações são gravadas.
É também suportada a compressão e encriptação autenticada, permitindo assim a realização de “backups” para destinos que não são totalmente confiáveis.
As principais características deste software são:

* Gestão eficiente de memória;
* Velocidade
* Encriptação de dados
* Compressão
* Off-site Backups
* Backups montáveis como sistemas de ficheiros
* Fácil instalação em diferentes plataformas

###Utilização Básica

Para usar o borg basta inicializar um novo repositório e criar um arquivo ex: Saturday1 que irá conter o backup de por  exemplo ~/Documents:

`$ borg init /path/to/repo` <br>
`$ borg create /path/to/repo::Saturday1 ~/Documents`

###Compatibilidade
* Linux;
* Mac OS X;
* FreeBSD;
* OpenBSD and NetBSD (no xattrs/ACLs support or binaries yet).

##Relatórios ESOF

[Software Processes](1.Software Processes.md)
