Using fsk, soapy, and sound gensios
===================================

The fsk, soapy, and sound gensio allow you to build software modems
for communication over radios, either directly with an SDR, or
indirectly with a sound card connected to a radio.

Using them without some sort of program (which will probably be
written) is a little complicated, though.  This document should help
with the basic concepts and give some general information.

Using soapy
===========

The soapy gensio is a thin wrapper over the SoapySDR library.  Some
information about how to use it is given in the gensio.5 man page.
You will need to look there for determining how to choose the SDR
device.

If you want to dump data from an SDR to a file, do something like:

```
gensiot -d -d -i 'file(outfile=dump1.raw,create)' \
  'soapy(frequency=435.6975M,inchannel=0,rate=2.5M,bandwidth=200K),driver=miri'
```

You can use ^C to stop it.

The frequency sets the *center* frequency of the SDR and translates
the frequencies down so that frequency will be the zero frequency in
the supplied data.  Frequencies below the center frequency will be
negative frequencies, above will be positive, up to the bandwidth in
either direction.  If you don't understand this, it's too much to
cover here, you need to find a tutorial on DSP and I/Q processing.

But the negative frequencies seem to not work with FSK.  FSK allows
this, but for some reason it doesn't work.  This hasn't been analyzed,
but I suspect it has to do with DC bias or the short measurement
windows not having enough resolution.

For FSK, you need to modify the frequency based on the data rate.  You
might think that you can shift it so the mark frequency is bps and the
space frequency is bps/2.  But especially for MSK, DC bias will again
cause issues on receive if it's present.  You could apply a high-pass
filter (one is present in the fsk gensio) but that will have a
significant effect on the space frequency because it's so close to
zero.

The solution for receive is to shift the frequencies up so that DC
bias doesn't affect them.  Shift the frequency so that the space
frequency is bps above 0, and the mark frequency is at (bps + 3 / 2)
above 0.  For instance, if your center frequency is 435.76MHz
(435760000), and your datarate is 50000bps, you would use the
following calculation to get the actual frequency to tune to:

```
435760000 - (50000 * 5 / 4) = 435697500
```

then set space to 50000 and mark to 75000.

For transmit, you want the mark and space frequencies to be bps/2 and
bps for MSK to work.  So for transmit, you set the actual frequency to:

```
435760000 - (50000 * 3 / 4) = 435722500
```

and set space to 25000 and mark to 50000.

Note that the mark and space frequencies given above will be the
default for the fsk gensio based upon the bps setting.

If you set the "freqadj" option to the fsk gensio, it will
automatically adjust the frequency for the child gensio as described
above.  If using fsk on top of soapy, you should almost certainly do
this.  That, along with the default mark and space frequencies, will
result in MSK with minimal settings.

The data that comes from/goes to soapy depends on the SDR, but it will
either be complex floating point (floatc) or real floating point
(float) numbers depending on the SDR.

Viewing SDR and sound data
==========================

It is often useful to be able to see the sound or SDR output visually.
I use audacity to do this.  To see the dump we created above, open
audacity, chose "File" then "Import" then "Raw data..." then choose
dump1.raw.

You will get a window with various parameters.  Set the Encoding to
32-bit floating point.  Byte order should be default endianness.  If
the SDR output is complex, choose "2 Channels", otherwise choose "1
Channel".  Leave the rest alone.

The sample rate for audacity only goes to 384k, so it doesn't go to
2.5M like we sampled above.  However, that doesn't matter.  Just
always choose the default value there, and things will remain
consistent.  Just remember that if you use any audacity filters or
effects you will need to adjust the frequencies.

Depending on the SDR and its default gain setting, the data may not be
viewable.  The values don't matter to the fsk gensio but audacity cuts
off at +/-1.0.  If things are seriously clipped when viewing in
audacity, you can adjust the gain on the soapy gensio to make it
viewable.

Using fsk on top of soapy
=========================

To put FSK on top of soapy, do something like:

```
gensiot -d -d -i 'file(outfile=dump1.data,create)' \
   'fsk(debug=0x00,bps=50000,tx=off,freqadj),
    soapy(frequency=435.67M,inchannel=0,rate=2.5M,bandwidth=200K),
      driver=miri'
```

This will FSK decode the data.  It uses MSK by default, so the mark
frequency will be the same as bps and the space frequency will be half
that.  We are only receiving, so tx is set to off so it doesn't try to
use the transmitter.

The raw FSK bits will be dumped into the outfile specified.

The fsk gensio has built-in filters for pre-processing the data.  See
the gensio.5 man page for details on those.  If you want to see the
output of the filters before FSK processing, you can set the debug
value to "0x20" and it will dump that to a file named "t1".  You can
view this with audacity as before.

To use the axfec gensio on top of this, you would do:

```
gensiot -d -d -i 'file(outfile=dump1.data,create)' \
   'axfec(debug=0x1f),
    fsk(debug=0x00,bps=50000,tx=off,uncert,certmult=50),
    soapy(frequency=435.67M,inchannel=0,rate=2.5M,bandwidth=200K),
      driver=miri'
```

The uncert and certmult setting are describe in the gensio.5 man page.
They are used to transfer information from fsk to the layer about it
about how sure it is that the given bits are correct.  The axfec
gensio uses this in the convolutional decoder to do soft decoding, and
it makes a huge difference in performance.

However, you need to set certmult properly, and it depends on a lot of
things.  With debug=0x1f on axfec, it will dump the uncertainty
values.  You want to set it so the uncertainty values are spread out
between 0 and 50.  50 is the maximum value for uncertainty (it's a
percentage, if it was more than 50 you would have chosen the other
value).

certmult is given in a certainty value, but the values coming up from
the fsk will be in uncertainty (100 - certainty).  So the larger you
make certmult, the smaller the uncertainty values will be.

Feeding saved data into fsk
===========================

If you have saved a file from soapy or a sound gensio, you can feed
that to fsk using the sound gensio in file mode with something like:

```
gensiot -d -d -i 'file(outfile=dump1.data,create)' \
    'axfec(debug=0x1f),
     fsk(debug=0x00,format=floatc,bufsize=512,bps=50000,readbuf=1,
         uncert,certmult=50),
     sound(2500000-1-float,type=file,outdev=/dev/null),dump1.raw'
```

Note that fsk reads the sample rate from the sound gensio, so the
sample rate there must be the same as the sample rate used to store
the data.

This shows an example of using complex data.  The sound gensio doesn't
know about complex data, so we have to force things.  The
"format=floatc" forces fsk to use complex data from the sound gensio
even though it advertises "float" data.  And the buffer size
advertised by the sound gensio will be 1024, but for complex data we
need half that because each sample is two float values, thus
"bufsize=512".

This is primarily useful if you are working on the fsk gensio, trying
to debug things or tweak values.  You can save something and play it
over and over trying different things.

NOTE: The uncert does not work well on 19200bps.  It seems to work
fine with the other speeds.  The reason for this is unknown at the
moment.
