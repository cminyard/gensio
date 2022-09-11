====================================
The gensio AFSK modem implementation
====================================

The Audio Frequency Shift Keying (AFSK) modem implementation in gensio
is a fairly unusual implementation, both for modulation and
demodulation.  I am actually experimenting with something else, and
the AFSK modem was a way to play around and learn from something
basic.

Terminology
===========

In the document, I will be referring to various terms to keep things
short.  They are:

sample
  A single number in the data stream.  In the code, a sample include
  all the channels for a single unit of time (like two samples for
  stereo) but the modulator only cares about one channel.

DFT

  Discrete Fourier Transfor.  You may think "FFT", but an FFT is just
  an efficient implementation of a DFT.  You can use do a DFT at
  specific frequencies without having to do a full spectrum analysis.
  When I say "DFT at xxx", that's what I'm talking about.  It's just
  doing a convulution against the sine and cosine of frequency xxx,
  squaring each of them, then adding them together, and technically
  taking the square root.  That gives you the power at a specific
  frequency in the input signal.  (The code doesn't take a square
  root and instead compares the squared numbers, for efficiency.)

convsize
  The number of samples to make up a single convolution for the DFT.

bitsize
  The number of samples used for transmit blocks.

mark
  The "1" bit sent.  The code uses HDLC NRZ coding on top of this, so
  the actual bits of data don't match the mark and space, but the mark
  and space are what is sent and they are converted to/from the actual
  bits.

space
  The "0" bit sent.

data rate
  The speed of the data being send, usually in bits per second.

Modulation
==========

You could build a really simple modulator.  Basically, have two
bitsize blocks of signal, one for the mark frequency and one for the
space frequency.  That has some big problems:

* You can get a huge discontinuity in the signal if the end of one
  blocks is not in phase with the beginning of another block.  This
  results in massive spectral distortion.

* If the size of a block doesn't exactly match with the data rate, you
  will drift in time and it will be hard for a receiver to match up.
  For instance, a data rate of 44100Hz and 1200 bits per second results
  in a bitsize of 36.75.  You can't send partial samples in a digital
  system.

Normally, you would have a software oscillator and vary the frequency,
must like a VFO in an electrical circuit.  Unfortunately, that's a
fairly CPU intensive process compared to just sending blocks of data.

The gensio AFSK modulator is a directed-graph (digraph) driven data
block modulator.  Each node in the digraph represents a mark or a
space at a specific phase.  Each node has a pointer to which node is
next to send a mark or space, and the next node will be in phase with
the previous one.  This avoids the discontinuities.

If the block-size doesn't match up with the data rate a different
block with a different size is sent periodically to line things up.
So you have two different size nodes, and each node has 4 links to
other nodes, for mark and space for each sized node.

For a data rate of 1200 and a sample rate of 44100, this results in
118 nodes in the digraph.  Of course, each node doesn't have a full
waveform, a single sine wave is produced into a buffer and the nodes
point to the starting point they need, which saves a lot of space.  So
the memory usage isn't too bad.

For data rates very close to the sample rate, this probably won't work
very well.  But at sample rate 5-6 times the data rate, it's not too
bad.  And very efficient.

Demodulation
============

In a classic AFSK demodulator, you would have two data processing
chains, each would have a low-pass filter (generally IIR, for
simplicity because it doesn't need to have lots of nodes) at the
beginning, then a bandpass filter (generally FIR, for stability,
because IIR filters with lots of nodes tend to be unstable), then a
lowpass filter.  You would have one of these for the mark and space
frequencies, then you would compare the output.

You generally need some sort of Phase Locked Loop (PLL) at the outputs
to keep the receiver aligned with the transmitter, because their
sample clocks may not be quite the same.

There are various ways to compare the output, but that's beyond the
scope here.  The direwolf documentation has some good info on this.
See A-Better-APRS-Packet-Demodulator-Part-1-1200-baud.pdf in the
direwolf doc directory.

The gensio AFSK modem doesn't do this.  A low-pass filter is available
at the input, but in reality, it doesn't make much difference.  It
helps a little, maybe a 1% improvement in bad signal conditions.  So
it's on by default, but it's not that important, and it takes up 33%
of the processing time when running.

Instead of a FIR filter, the gensio AFSK modem does a DFT at the mark
and space frequencies.  This give the power at each frequency.
This has some good traits:

* It is substantially more efficient than a FIR filter.

* You don't need a low pass filter on the output, resulting in better
  efficiencies.

The efficiency difference is significant.  The gensio AFSK modem uses
20% of the CPU that direwolf uses.  However, this also has some
problems:

* If your convsize isn't lined up pretty close to the transmitter
  bitsize, you aren't going to get good results, because you will get
  some power from each frequency if one bit is different than the
  next.  So they need to be fairly close to in phase.

* Even if you are lined up at first, if the receiver and transmitter
  have sample clocks that are off enough, the phase will drift and you
  won't be in phase for long.  It's surprising how much drift can
  happen.

To combat these problems, the gensio AFSK modem does a number of things:

* When measuring a signal, the ratio of the mark and space power is
  used to give a certainty to the signal.  The higher the certainty,
  the more likely it is to be a good signal.

* A number of different DFTs done are around what it currently thinks
  the convsize alignment should be.  So, for instance, it does one
  starting two samples before, then one before, then at the alignment,
  then one sample after, and so on.  It chooses the one with the most
  certainty.  This helps with short-term transient noise, and...

* On a transition from mark to space or back, the convsize alignment
  is modified based upon which of DFTs was chosen.  This will
  compensate for drift.  It can only be done on transitions because
  otherwise you can't know how in line you are.

  It used to detect a constant significant drift (you are constantly
  aligning a lot in one direction), and put that in all the time to
  help with long periods where there are no transition.  This turned
  out to be unhelpful in the long run, improvements in the convsize
  alignment caused this to be unneeded.

* To help adapt to systems with different filtering on the two
  frequencies, the detector does a number of different detections with
  the power on the space and mark each amplified.  So, it will amplify
  the space frequency results by 3db and run that, then the mark and
  run that, then it will do them at 6db.

* If the certainty of a signal is too low, it will "split" the stream
  into two streams of bits, one with each choice.  At the end, the
  frame check should tell us which one was right.  This is sort of FEC
  without the FEC overhead in the protocol.  But the number of bits
  that can be corrected is constant per message.  And since you have
  to split all the streams for each choice.  You get 2^n streams per
  uncertain bit, so correcting more than a few bits can result in a
  lot of running streams.  To correct 5 bits you would need 32
  streams, 7 bits needs 128 streams, etc.  It makes a big difference,
  though.  From my measurements, 5 bits is plenty, and 32 streams can
  be done with good efficiency.

* On top of this, the certainty of each stream is calculated from the
  certainty of the uncertain bits.  Each time a stream is split, the
  new certainty is added on to the more certain bit's value, and
  1/certainty is added on to the less certain streams value.  So each
  stream carries a certainty of all the bit choices before it.  When a
  new split happens, if the new value has a higher certainty than an
  existing one, it will evict the least certain one.

* The boosting of the signals that the direwolf docs describe is
  implemented.

* Just like the modulation side, the algorithm adjust the alignment
  periodically to make up for the case where convsize is not an even
  value.  For instance, for a data rate of 1200 and a sample rate of
  41000, the convsize is 36.75 samples.  So it will do 3 37 sample
  DFTs then a 36 sample one.

Of course, the code doesn't actually do a bunch of individual DFTs
around the expected alignment.  You can go from one to the next by
subtracting off the first sample and adding one on to the end.  So
it's not much more work than a single DFT.

The current results aren't quite as good as direwolf.  In track 1 of
the TNC test signals that the direwolf docs mention, direwolf will
decode 1032 packets and gensio will decode 993.  But that's at 20% of
the CPU.  And that's only after a day or so of tuning it.  There are
things I can do to tune it and improve it, I think.

Anyway, something unique, I think.
