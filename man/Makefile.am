man_MANS = gensio.5 gensio_event.3 str_to_gensio.3

install-data-hook:
	$(LN_S) str_to_gensio.3 $(DESTDIR)$(man3dir)/str_to_gensio_child.3
	$(LN_S) str_to_gensio.3 $(DESTDIR)$(man3dir)/gensio_acc_str_to_gensio.3

uninstall-hook:
	-rm -f $(DESTDIR)$(man3dir)/str_to_gensio_child.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_acc_str_to_gensio.3

EXTRA_DIST = $(man_MANS)
