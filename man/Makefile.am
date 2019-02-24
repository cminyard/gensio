man_MANS = gensio.5 gensio_event.3 str_to_gensio.3 gensio_set_callback.3 \
	gensio_set_log_mask.3 gensio_os_funcs.3 gensio_err.3

install-data-hook:
	$(LN_S) str_to_gensio.3 $(DESTDIR)$(man3dir)/str_to_gensio_child.3
	$(LN_S) str_to_gensio.3 $(DESTDIR)$(man3dir)/gensio_acc_str_to_gensio.3
	$(LN_S) gensio_set_callback.3 $(DESTDIR)$(man3dir)/gensio_set_user_data.3
	$(LN_S) gensio_set_callback.3 $(DESTDIR)$(man3dir)/gensio_get_user_data.3
	$(LN_S) gensio_set_log_mask.3 $(DESTDIR)$(man3dir)/gensio_get_log_mask.3
	$(LN_S) gensio_set_log_mask.3 $(DESTDIR)$(man3dir)/gensio_log_level_to_str.3
	$(LN_S) gensio_set_log_mask.3 $(DESTDIR)$(man3dir)/gensio_vlog.3
	$(LN_S) gensio_set_log_mask.3 $(DESTDIR)$(man3dir)/gensio_log.3
	$(LN_S) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_default_os_hnd.3
	$(LN_S) gensio_err.3 $(DESTDIR)$(man3dir)/gensio_err_to_str.3

uninstall-hook:
	-rm -f $(DESTDIR)$(man3dir)/str_to_gensio_child.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_acc_str_to_gensio.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_set_user_data.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_get_user_data.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_get_log_mask.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_log_level_to_str.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_vlog.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_log.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_default_os_hnd.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_err_to_str.3

EXTRA_DIST = $(man_MANS)
