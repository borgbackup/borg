# we strip the obsoleted entries from the template, otherwise they are naively copied in
%.po: messages.pot
	msgattrib --no-obsolete $< | msgmerge -U $@ -

messages.pot: ../borg/*.py
	xgettext -k_ -kN_ --from-code utf-8 -s -o $@ $^
