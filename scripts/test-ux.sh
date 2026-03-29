set -x
# Stable argparse usage() wrapping when comparing to test-ux.sh.blessed_stderr.
export COLUMNS="${COLUMNS:-80}"
# Fixed paths; remove leftovers so each run matches test-ux.sh.blessed_stderr.
rm -rf /tmp/demo-repo
#errors that should be have helpful help

borg --repo /tmp/demo-repo init -e repokey-aes-ocb
borg --repo /tmp/demo-repo rcreate -e repokey-aes-ocb

#Typo suggestions (Did you mean ...?)

borg repo-creat
borg repoo-list
Borg1 -> Borg2 option hints

borg --repo /tmp/demo-repo list --glob-archives 'my*'
borg --repo /tmp/demo-repo create --numeric-owner test ~/data
borg --repo /tmp/demo-repo create --nobsdflags test ~/data
borg --repo /tmp/demo-repo create --remote-ratelimit 1000 test ~/data

#Missing encryption guidance for repo-create

borg --repo /tmp/demo-repo repo-create

#repo::archive migration help (BORG_REPO / --repo guidance)

borg --repo /tmp/demo-repo::test1 list

#Missing repo recovery hint (includes repo-create example + -e modes)

borg --repo /tmp/does-not-exist repo-info
borg --repo /tmp/does-not-exist list

#Common fixes block (missing repo / unknown command)

borg list
borg frobnicate

#Options are preserved by command-line correction.
