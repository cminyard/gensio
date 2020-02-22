
install(FILES gensio.5 DESTINATION ${CMAKE_INSTALL_FULL_MANDIR}/man5)

install(FILES gensio_event.3 str_to_gensio.3 gensio_set_callback.3
	gensio_set_log_mask.3 gensio_os_funcs.3 gensio_err.3 gensio_write.3
	gensio_get_raddr.3 gensio_raddr_to_str.3 gensio_open.3
	gensio_alloc_channel.3 gensio_close.3 gensio_control.3
	gensio_set_read_callback_enable.3 gensio_get_type.3 gensio_set_sync.3
	gensio_accepter_event.3 gensio_acc_set_callback.3
	gensio_acc_shutdown.3 gensio_acc_set_accept_callback_enable.3
	gensio_acc_control.3 gensio_acc_get_type.3 gensio_add_default.3
	str_to_gensio_accepter.3 gensio_acc_accept_s.3 gensio_acc_startup.3
	DESTINATION ${CMAKE_INSTALL_FULL_MANDIR}/man3)

macro(install_man3_symlink filepath sympath)
    install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${filepath} ${CMAKE_INSTALL_FULL_MANDIR}/man3/${sympath})")
    install(CODE "message(\"-- Created symlink: ${sympath} -> ${filepath}\")")
endmacro(install_man3_symlink)

install_man3_symlink(str_to_gensio.3 str_to_gensio_child.3)
install_man3_symlink(str_to_gensio.3 gensio_acc_str_to_gensio.3)
install_man3_symlink(gensio_set_callback.3 gensio_set_user_data.3)
install_man3_symlink(gensio_set_callback.3 gensio_get_user_data.3)
install_man3_symlink(gensio_set_log_mask.3 gensio_get_log_mask.3)
install_man3_symlink(gensio_set_log_mask.3 gensio_log_level_to_str.3)
install_man3_symlink(gensio_set_log_mask.3 gensio_vlog.3)
install_man3_symlink(gensio_set_log_mask.3 gensio_log.3)
install_man3_symlink(gensio_os_funcs.3 gensio_default_os_hnd.3)
install_man3_symlink(gensio_err.3 gensio_err_to_str.3)
install_man3_symlink(gensio_write.3 gensio_write_sg.3)
install_man3_symlink(gensio_open.3 gensio_open_s.3)
install_man3_symlink(gensio_open.3 gensio_open_nochild.3)
install_man3_symlink(gensio_open.3 gensio_open_nochild_s.3)
install_man3_symlink(gensio_close.3 gensio_close_s.3)
install_man3_symlink(gensio_close.3 gensio_disable.3)
install_man3_symlink(gensio_close.3 gensio_free.3)
install_man3_symlink(gensio_set_read_callback_enable.3
		     gensio_set_write_callback_enable.3)
install_man3_symlink(gensio_get_type.3 gensio_get_child.3)
install_man3_symlink(gensio_get_type.3 gensio_is_client.3)
install_man3_symlink(gensio_get_type.3 gensio_is_reliable.3)
install_man3_symlink(gensio_get_type.3 gensio_is_packet.3)
install_man3_symlink(gensio_get_type.3 gensio_is_message.3)
install_man3_symlink(gensio_get_type.3 gensio_is_authenticated.3)
install_man3_symlink(gensio_get_type.3 gensio_is_encrypted.3)
install_man3_symlink(gensio_set_sync.3 gensio_clear_sync.3)
install_man3_symlink(gensio_set_sync.3 gensio_read_s.3)
install_man3_symlink(gensio_set_sync.3 gensio_write_s.3)
install_man3_symlink(str_to_gensio_accepter.3 str_to_gensio_accepter_child.3)
install_man3_symlink(gensio_acc_set_callback.3 gensio_acc_set_user_data.3)
install_man3_symlink(gensio_acc_set_callback.3 gensio_acc_get_user_data.3)
install_man3_symlink(gensio_acc_shutdown.3 gensio_acc_shutdown_s.3)
install_man3_symlink(gensio_acc_shutdown.3 gensio_acc_disable.3)
install_man3_symlink(gensio_acc_shutdown.3 gensio_acc_free.3)
install_man3_symlink(gensio_acc_set_accept_callback_enable.3
		     gensio_acc_set_accept_callback_enable_cb.3)
install_man3_symlink(gensio_acc_set_accept_callback_enable.3
		     gensio_acc_set_accept_callback_enable_s.3)
install_man3_symlink(gensio_acc_get_type.3 gensio_acc_is_reliable.3)
install_man3_symlink(gensio_acc_get_type.3 gensio_acc_is_packet.3)
install_man3_symlink(gensio_acc_get_type.3 gensio_acc_is_message.3)
install_man3_symlink(gensio_add_default.3 gensio_set_default.3)
install_man3_symlink(gensio_add_default.3 gensio_get_default.3)
install_man3_symlink(gensio_add_default.3 gensio_get_defaultaddr.3)
install_man3_symlink(gensio_add_default.3 gensio_del_default.3)
install_man3_symlink(gensio_add_default.3 gensio_reset_defaults.3)
install_man3_symlink(gensio_acc_accept_s.3 gensio_acc_set_sync.3)
