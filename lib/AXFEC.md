AXFEC design and protocol
=========================

The AXFEC implements the FEC protocol as the OnSemi AX5043 radio does
it.  It's ... complicated.  As I've been working on the software for
this, playing with things, I've realized that the HDLC, FEC, and
interleaving state machine have to be tightly coupled to make this
work.  I'll explain how all this works.

When transmitting, you HDLC encode the data, then convolutional code
that, then interleave it.  That is then modulated and sent.

One the receive side, you have to get alignment for the interleaver to
work properly.  When you convolutional encode the initial HDLC flags
and then interleave it, you will get a specific unique sequence.
Here's the process:

Convolutionally encode some flags (0x7e).  The AX5043 requires that
you insert an 0 extra bit at the beginning of this process (probably due
to a bug in the receiver), but here's a command with a convolutional
coder:

```
convcode -p 023 -p 035 5 001111110011111100111111001111110
  00001110110110100100100111011010010010011101101001001001110110100100011100
```

Note that you read the bits from left to right *whereas the data in
byte format is right to left).  The first 16 bits don't matter, the
coder isn't primed, but each 16 bit segment after that, you will
notice, is the same:

```
  0100100111011010
```

However, probably due to another hardware bug, the AX5043 flips the
value of the first bit, third bit, fifth bit, and every other bit out
of the coder.  So we have:

```
1110001101110000
```

The interleaver works as a 4x4 matrix, you put the data in row-wise, and pull it out column-wise.  Here's the matrix:

```
1110
0011
0111
0000
```

Reading out column-wise, we get:

```
1000101011100110
```

and that's our synchronization sequence.  This will occur over and
over while flags are being sent.  You will want to use two of these in
a row to get a 32-bit sequence, making this happen by random chance
then becomes a one in 4 billion chance.

So once the interleaver sees this sequence, it will start
de-interleaving the data, flipping the proper bits, and shipping it to
the convolutional coder.  However, you have two problems: You don't
want to have all those beginning flags in the convolutional decoder,
and you don't know where the end of the packet is.

For the first problem, it's a problem because all those extra flags at
the beginning just waste space in the decoder trellis, and you can
have a lot of them.  You don't want to just look until the
synchronization sequences end, though, as a bit flip may cause that to
fail.  You want to feed the data into the decoder and use that.  To
solve this, while you are getting flags out of the decoder, you are
resetting the trellis without resetting the state.  You kind of have
to know how convolutional coders works, but that will work just fine.
You can always stick a flag back on at the beginning if your HDLC
processor needs it.  But it's not necessary, you've already done the
flag processing in this process.

You probably also want to make sure you get some flags in a row before
you actually say you've got a good sequence.  Just in case.  So you
get maybe 6 flags, then you tell the interleaver to lock it's
interleaving and stop looking for the synchronization sequence.  (See
the next section on how to get partial data out of the decoder.)

For the second problem, there is no packet length sent, and neither
the docs nor gr-satellite mentions any sort of block length, so it
appears to code the entire packet as one unit.  You could look for the
raw magic sequence, but again, bit flips may cause you to miss that.
To find the end, you have to watch for a flag coming out of the
decoder.  This is more difficult than you might imagine, because you
actually read the decoder trellis backwards to get the data out.  So
as you are putting bits into the decoder, you are doing a short run
backwards through the trellis periodically looking for a flag at the
end.  You also don't want to read it right at the end, you want the
last bits to be a tail and read before them for proper decoding.

This may not be as reliable as you would like, as what comes out
earlier in a convolutional decoder may change depending on what comes
later but I don't know of another way to do it.  You could do a CRC
check on the packet at that point and continue if it fails.

Once you see a final flag, you can tell the interleaver to start
looking for the synchronization sequence again.  And you can take the
packet, unstuff the stuffed zeros, CRC check it, and deliver it.

Except that the AX5043 behaves strangely here.  It encodes an HDLC
flag at the end of the data, then enough zeros to fill out the rest of
the interleaver.  It then puts out a couple of more encoded flags.  If
you just stopped after the first end flags, you would see these flags
after the zeros and start a new packet.  So you have to account for
that, too.

As you can see, all of these parts have to be fairly custom for this process.

I think I have captured everything here.  It's been a long road to get
all this information and think it through.
