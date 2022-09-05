man_MANS = gensio.5 gensio_event.3 str_to_gensio.3 gensio_set_callback.3 \
	gensio_set_log_mask.3 gensio_os_funcs.3 gensio_err.3 gensio_write.3 \
	gensio_open.3 gensio_alloc_channel.3 gensio_close.3 gensio_control.3 \
	gensio_set_read_callback_enable.3 gensio_get_type.3 gensio_set_sync.3 \
	gensio_accepter_event.3 gensio_acc_set_callback.3 \
	gensio_acc_shutdown.3 gensio_acc_set_accept_callback_enable.3 \
	gensio_acc_control.3 gensio_acc_get_type.3 gensio_add_default.3 \
	str_to_gensio_accepter.3 gensio_acc_accept_s.3 gensio_acc_startup.3 \
	sergensio.5 gensio_to_sergensio.3 sergensio_baud.3 \
	sergensio_b_alloc.3 sergensio_event.3 gensio_mdns.3

# Note that $(LN_SF) is set in configure.ac

install-data-hook:
	$(LN_SF) str_to_gensio.3 $(DESTDIR)$(man3dir)/str_to_gensio_child.3
	$(LN_SF) str_to_gensio.3 $(DESTDIR)$(man3dir)/gensio_acc_str_to_gensio.3
	$(LN_SF) str_to_gensio.3 $(DESTDIR)$(man3dir)/gensio_terminal_alloc.3
	$(LN_SF) str_to_gensio.3 $(DESTDIR)$(man3dir)/gensio_filter_alloc.3
	$(LN_SF) gensio_set_callback.3 $(DESTDIR)$(man3dir)/gensio_set_user_data.3
	$(LN_SF) gensio_set_callback.3 $(DESTDIR)$(man3dir)/gensio_get_user_data.3
	$(LN_SF) gensio_set_log_mask.3 $(DESTDIR)$(man3dir)/gensio_get_log_mask.3
	$(LN_SF) gensio_set_log_mask.3 $(DESTDIR)$(man3dir)/gensio_log_level_to_str.3
	$(LN_SF) gensio_set_log_mask.3 $(DESTDIR)$(man3dir)/gensio_vlog.3
	$(LN_SF) gensio_set_log_mask.3 $(DESTDIR)$(man3dir)/gensio_log.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_default_os_hnd.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_unix_funcs_alloc.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_win_funcs_alloc.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_proc_setup.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_proc_cleanup.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_proc_unix_get_wait_sigset.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_new_thread.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_wait_thread.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_free.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_proc_register_term_handler.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_proc_register_reload_handler.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_proc_winsize_handler.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_zalloc.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_zfree.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_alloc_lock.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_free_lock.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_lock.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_unlock.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_get_monotonic_time.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_alloc_timer.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_free_timer.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_start_timer.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_start_timer_abs.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_stop_timer.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_stop_timer_with_done.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_alloc_runner.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_free_runner.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_run.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_set_vlog.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_service.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_handle_fork.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_alloc_waiter.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_free_waiter.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_wait.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_wait_intr.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_wait_intr_sigmask.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_wake.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_set_data.3
	$(LN_SF) gensio_os_funcs.3 $(DESTDIR)$(man3dir)/gensio_os_funcs_get_data.3
	$(LN_SF) gensio_err.3 $(DESTDIR)$(man3dir)/gensio_err_to_str.3
	$(LN_SF) gensio_write.3 $(DESTDIR)$(man3dir)/gensio_write_sg.3
	$(LN_SF) gensio_open.3 $(DESTDIR)$(man3dir)/gensio_open_s.3
	$(LN_SF) gensio_open.3 $(DESTDIR)$(man3dir)/gensio_open_nochild.3
	$(LN_SF) gensio_open.3 $(DESTDIR)$(man3dir)/gensio_open_nochild_s.3
	$(LN_SF) gensio_close.3 $(DESTDIR)$(man3dir)/gensio_close_s.3
	$(LN_SF) gensio_close.3 $(DESTDIR)$(man3dir)/gensio_disable.3
	$(LN_SF) gensio_close.3 $(DESTDIR)$(man3dir)/gensio_free.3
	$(LN_SF) gensio_set_read_callback_enable.3 $(DESTDIR)$(man3dir)/gensio_set_write_callback_enable.3
	$(LN_SF) gensio_get_type.3 $(DESTDIR)$(man3dir)/gensio_get_child.3
	$(LN_SF) gensio_get_type.3 $(DESTDIR)$(man3dir)/gensio_is_client.3
	$(LN_SF) gensio_get_type.3 $(DESTDIR)$(man3dir)/gensio_is_reliable.3
	$(LN_SF) gensio_get_type.3 $(DESTDIR)$(man3dir)/gensio_is_packet.3
	$(LN_SF) gensio_get_type.3 $(DESTDIR)$(man3dir)/gensio_is_message.3
	$(LN_SF) gensio_get_type.3 $(DESTDIR)$(man3dir)/gensio_is_authenticated.3
	$(LN_SF) gensio_get_type.3 $(DESTDIR)$(man3dir)/gensio_is_encrypted.3
	$(LN_SF) gensio_set_sync.3 $(DESTDIR)$(man3dir)/gensio_clear_sync.3
	$(LN_SF) gensio_set_sync.3 $(DESTDIR)$(man3dir)/gensio_read_s.3
	$(LN_SF) gensio_set_sync.3 $(DESTDIR)$(man3dir)/gensio_write_s.3
	$(LN_SF) str_to_gensio_accepter.3 $(DESTDIR)$(man3dir)/str_to_gensio_accepter_child.3
	$(LN_SF) str_to_gensio_accepter.3 $(DESTDIR)$(man3dir)/gensio_terminal_acc_alloc.3
	$(LN_SF) str_to_gensio_accepter.3 $(DESTDIR)$(man3dir)/gensio_filter_acc_alloc.3
	$(LN_SF) gensio_acc_set_callback.3 $(DESTDIR)$(man3dir)/gensio_acc_set_user_data.3
	$(LN_SF) gensio_acc_set_callback.3 $(DESTDIR)$(man3dir)/gensio_acc_get_user_data.3
	$(LN_SF) gensio_acc_shutdown.3 $(DESTDIR)$(man3dir)/gensio_acc_shutdown_s.3
	$(LN_SF) gensio_acc_shutdown.3 $(DESTDIR)$(man3dir)/gensio_acc_disable.3
	$(LN_SF) gensio_acc_shutdown.3 $(DESTDIR)$(man3dir)/gensio_acc_free.3
	$(LN_SF) gensio_acc_set_accept_callback_enable.3 $(DESTDIR)$(man3dir)/gensio_acc_set_accept_callback_enable_cb.3
	$(LN_SF) gensio_acc_set_accept_callback_enable.3 $(DESTDIR)$(man3dir)/gensio_acc_set_accept_callback_enable_s.3
	$(LN_SF) gensio_acc_get_type.3 $(DESTDIR)$(man3dir)/gensio_acc_is_reliable.3
	$(LN_SF) gensio_acc_get_type.3 $(DESTDIR)$(man3dir)/gensio_acc_is_packet.3
	$(LN_SF) gensio_acc_get_type.3 $(DESTDIR)$(man3dir)/gensio_acc_is_message.3
	$(LN_SF) gensio_add_default.3 $(DESTDIR)$(man3dir)/gensio_set_default.3
	$(LN_SF) gensio_add_default.3 $(DESTDIR)$(man3dir)/gensio_get_default.3
	$(LN_SF) gensio_add_default.3 $(DESTDIR)$(man3dir)/gensio_get_defaultaddr.3
	$(LN_SF) gensio_add_default.3 $(DESTDIR)$(man3dir)/gensio_del_default.3
	$(LN_SF) gensio_add_default.3 $(DESTDIR)$(man3dir)/gensio_reset_defaults.3
	$(LN_SF) gensio_acc_accept_s.3 $(DESTDIR)$(man3dir)/gensio_acc_set_sync.3
	$(LN_SF) gensio_to_sergensio.3 $(DESTDIR)$(man3dir)/sergensio_to_gensio.3
	$(LN_SF) gensio_to_sergensio.3 $(DESTDIR)$(man3dir)/sergensio_get_user_data.3
	$(LN_SF) gensio_to_sergensio.3 $(DESTDIR)$(man3dir)/sergensio_is_client.3
	$(LN_SF) sergensio_baud.3 $(DESTDIR)$(man3dir)/sergensio_datasize.3
	$(LN_SF) sergensio_baud.3 $(DESTDIR)$(man3dir)/sergensio_parity.3
	$(LN_SF) sergensio_baud.3 $(DESTDIR)$(man3dir)/sergensio_stopbits.3
	$(LN_SF) sergensio_baud.3 $(DESTDIR)$(man3dir)/sergensio_flowcontrol.3
	$(LN_SF) sergensio_baud.3 $(DESTDIR)$(man3dir)/sergensio_iflowcontrol.3
	$(LN_SF) sergensio_baud.3 $(DESTDIR)$(man3dir)/sergensio_sbreak.3
	$(LN_SF) sergensio_baud.3 $(DESTDIR)$(man3dir)/sergensio_dtr.3
	$(LN_SF) sergensio_baud.3 $(DESTDIR)$(man3dir)/sergensio_rts.3
	$(LN_SF) sergensio_baud.3 $(DESTDIR)$(man3dir)/sergensio_signature.3
	$(LN_SF) sergensio_baud.3 $(DESTDIR)$(man3dir)/sergensio_linestate.3
	$(LN_SF) sergensio_baud.3 $(DESTDIR)$(man3dir)/sergensio_modemstate.3
	$(LN_SF) sergensio_baud.3 $(DESTDIR)$(man3dir)/sergensio_flowcontrol_state.3
	$(LN_SF) sergensio_baud.3 $(DESTDIR)$(man3dir)/sergensio_flush.3
	$(LN_SF) sergensio_baud.3 $(DESTDIR)$(man3dir)/sergensio_send_break.3
	$(LN_SF) sergensio_baud.3 $(DESTDIR)$(man3dir)/sergensio_cts.3
	$(LN_SF) sergensio_baud.3 $(DESTDIR)$(man3dir)/sergensio_dcd_dsr.3
	$(LN_SF) sergensio_baud.3 $(DESTDIR)$(man3dir)/sergensio_ri.3
	$(LN_SF) sergensio_b_alloc.3 $(DESTDIR)$(man3dir)/sergensio_b_free.3
	$(LN_SF) sergensio_b_alloc.3 $(DESTDIR)$(man3dir)/sergensio_baud_b.3
	$(LN_SF) sergensio_b_alloc.3 $(DESTDIR)$(man3dir)/sergensio_datasize_b.3
	$(LN_SF) sergensio_b_alloc.3 $(DESTDIR)$(man3dir)/sergensio_parity_b.3
	$(LN_SF) sergensio_b_alloc.3 $(DESTDIR)$(man3dir)/sergensio_stopbits_b.3
	$(LN_SF) sergensio_b_alloc.3 $(DESTDIR)$(man3dir)/sergensio_flowcontrol_b.3
	$(LN_SF) sergensio_b_alloc.3 $(DESTDIR)$(man3dir)/sergensio_iflowcontrol_b.3
	$(LN_SF) sergensio_b_alloc.3 $(DESTDIR)$(man3dir)/sergensio_sbreak_b.3
	$(LN_SF) sergensio_b_alloc.3 $(DESTDIR)$(man3dir)/sergensio_dtr_b.3
	$(LN_SF) sergensio_b_alloc.3 $(DESTDIR)$(man3dir)/sergensio_rts_b.3
	$(LN_SF) sergensio_b_alloc.3 $(DESTDIR)$(man3dir)/sergensio_cts_b.3
	$(LN_SF) sergensio_b_alloc.3 $(DESTDIR)$(man3dir)/sergensio_dcd_dsr_b.3
	$(LN_SF) sergensio_b_alloc.3 $(DESTDIR)$(man3dir)/sergensio_ri_b.3
	$(LN_SF) gensio_mdns.3 $(DESTDIR)$(man3dir)/gensio_alloc_mdns.3
	$(LN_SF) gensio_mdns.3 $(DESTDIR)$(man3dir)/gensio_free_mdns.3
	$(LN_SF) gensio_mdns.3 $(DESTDIR)$(man3dir)/gensio_mdns_add_service.3
	$(LN_SF) gensio_mdns.3 $(DESTDIR)$(man3dir)/gensio_mdns_remove_service.3
	$(LN_SF) gensio_mdns.3 $(DESTDIR)$(man3dir)/gensio_mdns_add_watch.3
	$(LN_SF) gensio_mdns.3 $(DESTDIR)$(man3dir)/gensio_mdns_remove_watch.3

RM_F = -rm -f

uninstall-hook:
	$(RM_F) $(DESTDIR)$(man3dir)/str_to_gensio_child.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_terminal_alloc.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_filter_alloc.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_acc_str_to_gensio.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_set_user_data.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_get_user_data.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_get_log_mask.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_log_level_to_str.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_vlog.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_log.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_default_os_hnd.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_unix_funcs_alloc.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_win_funcs_alloc.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_os_proc_setup.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_os_proc_cleanup.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_os_proc_unix_get_wait_sigset.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_os_new_thread.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_os_wait_thread.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_write_sg.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_err_to_str.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_open_s.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_open_nochild.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_open_nochild_s.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_close_s.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_disable.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_free.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_set_write_callback_enable.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_get_child.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_is_client.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_is_reliable.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_is_packet.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_is_message.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_is_authenticated.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_is_encrypted.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_clear_sync.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_read_s.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_write_s.3
	$(RM_F) $(DESTDIR)$(man3dir)/str_to_gensio_accepter_child.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_terminal_acc_alloc.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_filter_acc_alloc.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_acc_set_user_data.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_acc_get_user_data.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_acc_shutdown_s.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_acc_disable.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_acc_free.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_acc_set_accept_callback_enable_cb.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_acc_set_accept_callback_enable_s.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_acc_is_reliable.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_acc_is_packet.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_acc_is_message.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_set_default.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_get_default.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_get_defaultaddr.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_del_default.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_reset_defaults.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_acc_set_sync.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_to_gensio.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_get_user_data.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_is_client.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_datasize.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_parity.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_stopbits.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_flowcontrol.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_iflowcontrol.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_sbreak.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_dtr.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_rts.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_cts.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_dcd_dsr.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_ri.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_signature.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_linestate.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_modemstate.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_flowcontrol_state.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_flush.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_send_break.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_b_free.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_baud_b.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_datasize_b.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_parity_b.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_stopbits_b.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_flowcontrol_b.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_iflowcontrol_b.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_sbreak_b.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_dtr_b.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_rts_b.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_cts_b.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_dcd_dsr_b.3
	$(RM_F) $(DESTDIR)$(man3dir)/sergensio_ri_b.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_alloc_mdns.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_free_mdns.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_mdns_add_service.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_mdns_remove_service.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_mdns_add_watch.3
	$(RM_F) $(DESTDIR)$(man3dir)/gensio_mdns_remove_watch.3

EXTRA_DIST = $(man_MANS)
