man_MANS = gensio.5 gensio_event.3 str_to_gensio.3 gensio_set_callback.3 \
	gensio_set_log_mask.3 gensio_os_funcs.3 gensio_err.3 gensio_write.3 \
	gensio_get_raddr.3 gensio_raddr_to_str.3 gensio_open.3 \
	gensio_open_channel.3 gensio_close.3 gensio_control.3 \
	gensio_set_read_callback_enable.3 gensio_get_type.3 gensio_set_sync.3 \
	gensio_accepter_event.3 gensio_acc_set_callback.3 \
	gensio_acc_shutdown.3 gensio_acc_set_accept_callback_enable.3 \
	gensio_acc_control.3 gensio_acc_get_type.3

install-data-hook:
	$(LN_S) -f str_to_gensio.3 $(DESTDIR)$(man3dir)/str_to_gensio_child.3
	$(LN_S) -f str_to_gensio.3 $(DESTDIR)$(man3dir)/gensio_acc_str_to_gensio.3
	$(LN_S) -f gensio_set_callback.3 $(DESTDIR)$(man3dir)/gensio_set_user_data.3
	$(LN_S) -f gensio_set_callback.3 $(DESTDIR)$(man3dir)/gensio_get_user_data.3
	$(LN_S) -f gensio_set_log_mask.3 $(DESTDIR)$(man3dir)/gensio_get_log_mask.3
	$(LN_S) -f gensio_set_log_mask.3 $(DESTDIR)$(man3dir)/gensio_log_level_to_str.3
	$(LN_S) -f gensio_set_log_mask.3 $(DESTDIR)$(man3dir)/gensio_vlog.3
	$(LN_S) -f gensio_set_log_mask.3 $(DESTDIR)$(man3dir)/gensio_log.3
	$(LN_S) -f gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_default_os_hnd.3
	$(LN_S) -f gensio_err.3 $(DESTDIR)$(man3dir)/gensio_err_to_str.3
	$(LN_S) -f gensio_open.3 $(DESTDIR)$(man3dir)/gensio_open_s.3
	$(LN_S) -f gensio_open.3 $(DESTDIR)$(man3dir)/gensio_open_nochild.3
	$(LN_S) -f gensio_open.3 $(DESTDIR)$(man3dir)/gensio_open_nochild_s.3
	$(LN_S) -f gensio_open_channel.3 $(DESTDIR)$(man3dir)/gensio_open_channel_s.3
	$(LN_S) -f gensio_close.3 $(DESTDIR)$(man3dir)/gensio_close_s.3
	$(LN_S) -f gensio_close.3 $(DESTDIR)$(man3dir)/gensio_disable.3
	$(LN_S) -f gensio_close.3 $(DESTDIR)$(man3dir)/gensio_free.3
	$(LN_S) -f gensio_set_read_callback_enable.3 $(DESTDIR)$(man3dir)/gensio_set_write_callback_enable.3
	$(LN_S) -f gensio_get_type.3 $(DESTDIR)$(man3dir)/gensio_get_child.3
	$(LN_S) -f gensio_get_type.3 $(DESTDIR)$(man3dir)/gensio_is_client.3
	$(LN_S) -f gensio_get_type.3 $(DESTDIR)$(man3dir)/gensio_is_reliable.3
	$(LN_S) -f gensio_get_type.3 $(DESTDIR)$(man3dir)/gensio_is_packet.3
	$(LN_S) -f gensio_get_type.3 $(DESTDIR)$(man3dir)/gensio_is_authenticated.3
	$(LN_S) -f gensio_get_type.3 $(DESTDIR)$(man3dir)/gensio_is_encrypted.3
	$(LN_S) -f gensio_set_sync.3 $(DESTDIR)$(man3dir)/gensio_clear_sync.3
	$(LN_S) -f gensio_set_sync.3 $(DESTDIR)$(man3dir)/gensio_read_s.3
	$(LN_S) -f gensio_set_sync.3 $(DESTDIR)$(man3dir)/gensio_write_s.3
	$(LN_S) -f gensio_acc_set_callback.3 $(DESTDIR)$(man3dir)/gensio_acc_set_user_data.3
	$(LN_S) -f gensio_acc_set_callback.3 $(DESTDIR)$(man3dir)/gensio_acc_get_user_data.3
	$(LN_S) -f gensio_acc_shutdown.3 $(DESTDIR)$(man3dir)/gensio_acc_shutdown_s.3
	$(LN_S) -f gensio_acc_shutdown.3 $(DESTDIR)$(man3dir)/gensio_acc_disable.3
	$(LN_S) -f gensio_acc_shutdown.3 $(DESTDIR)$(man3dir)/gensio_acc_free.3
	$(LN_S) -f gensio_acc_set_accept_callback_enable.3 $(DESTDIR)$(man3dir)/gensio_acc_set_accept_callback_enable_cb.3
	$(LN_S) -f gensio_acc_set_accept_callback_enable.3 $(DESTDIR)$(man3dir)/gensio_acc_set_accept_callback_enable_s.3
	$(LN_S) -f gensio_acc_get_type.3 $(DESTDIR)$(man3dir)/gensio_acc_is_reliable.3
	$(LN_S) -f gensio_acc_get_type.3 $(DESTDIR)$(man3dir)/gensio_acc_is_packet.3

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
	-rm -f $(DESTDIR)$(man3dir)/gensio_open_s.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_open_nochild.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_open_nochild_s.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_open_channel_s.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_close_s.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_disable.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_free.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_set_write_callback_enable.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_get_child.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_is_client.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_is_reliable.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_is_packet.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_is_authenticated.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_is_encrypted.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_clear_sync.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_read_s.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_write_s.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_acc_set_user_data.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_acc_get_user_data.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_acc_shutdown_s.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_acc_disable.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_acc_free.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_acc_set_accept_callback_enable_cb.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_acc_set_accept_callback_enable_s.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_acc_is_reliable.3
	-rm -f $(DESTDIR)$(man3dir)/gensio_acc_is_packet.3

EXTRA_DIST = $(man_MANS)
