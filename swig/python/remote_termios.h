/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

/*
 * Functions for accessing termios through the Linux serialsim device.
 */
extern int remote_termios(struct termios *termios, int fd);
extern int remote_rs485(int fd, char **rstr);
extern int sremote_mctl(unsigned int mctl, int fd);
extern int sremote_sererr(unsigned int err, int fd);
extern int sremote_null_modem(bool val, int fd);
extern int gremote_mctl(unsigned int *mctl, int fd);
extern int gremote_sererr(unsigned int *err, int fd);
extern int gremote_null_modem(int *val, int fd);
