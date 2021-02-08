
#include <iostream>
#include <gensio/gensio>
using namespace std;
using namespace gensio;

int main(int argc, char *argv[])
{
    struct gensio_os_funcs *o;
    int err;
    err = gensio_default_os_hnd(0, &o);
    if (err) {
	cerr << "OS handler alloc failed: " << gensio_err_to_str(err) << endl;
	return 1;
    }
    Waiter w(o);
    Serial_Gensio *sg = (Serial_Gensio *)
	gensio_alloc("serialdev,/dev/ttyEcho0,9600N81", o, NULL);
    gensio_time t;
    unsigned int v;

    err = 0;
    sg->open_s();
    cout << "Allocated" << endl;
    cout << "Validating baud is 9600" << endl;
    v = 0;
    sg->baud_s(&v);
    if (v != 9600) {
	err = 1;
	cout << "*** Baud was not 9600" << endl;
    }
    cout << "Setting baud to 19200" << endl;
    v = 19200;
    sg->baud_s(&v);
    if (v != 19200) {
	err = 1;
	cout << "*** Baud was not 19200" << endl;
    } else {
	cout << "baud set to 19200" << endl;
    }
    cout << "Closing" << endl;
    sg->close_s();
    sg->free();

    return 0;
}
