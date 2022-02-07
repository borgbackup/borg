{
	gpg --recv-keys "6D5B EF9A DD20 7580 5747 B70F 9F88 FB52 FAF7 B393"
} &> /dev/null  # Do not pollute the asciinema output.
# The above redirection can be removed for troubleshhting

expect /asciinema/install.tcl
