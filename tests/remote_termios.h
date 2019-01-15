
/* Defined in another file to avoid string type collisions. */
extern int remote_termios(struct termios *termios, int fd);
extern int remote_rs485(int fd, char **rstr);
extern int sremote_mctl(unsigned int mctl, int fd);
extern int sremote_sererr(unsigned int err, int fd);
extern int sremote_null_modem(bool val, int fd);
extern int gremote_mctl(unsigned int *mctl, int fd);
extern int gremote_sererr(unsigned int *err, int fd);
extern int gremote_null_modem(int *val, int fd);
