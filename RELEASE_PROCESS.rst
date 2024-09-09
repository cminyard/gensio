This is a list of things I do when getting a release ready, mostly
here for me to follow when doing a release.

After everything is ready, on Linux(x86_64 and arm64), Windows, MacOS,
and FreeBSD do:

  mkdir Ztest
  ../configure --enable-internal-trace
  make -j<n>
  make check
  make install DESTDIR=$HOME/tmp/install
  rm -rf $HOME/tmp/install
  cd ..
  rm -rf Ztest

and obviously everything should pass on all platforms.  Before running
tests on Linux, make sure the serialsim driver is installed so it will
be able to run all the tests.

Install it on a local system, make sure the serialsim driver is
installed, and run the ser2net tests.

Then create the new version.  To do this:

* Edit configure.ac, change the version in both places right at the
  top.  Also fix it in gensio.iss in MyAppVersion.

* If necessary, update GENSIO_LIB_VERSION in configure.ac.  Do an
  "info libtool" and look under "Versioning" then "Updating version
  info" for the rules, which are complicated.  The library version
  will be "C - A", if that changes from the previous version, you
  need to update MyAppLibVersion in gensio.iss.  Note that if you
  change C and A together (like if there were only additions and
  not removals or changes to the API) the version doesn't change.

* Commit those changes with the subject "Move to version x.x.x"

* Tag the current version with "git tag -s vx.x.x".  I usually just
  use "Gensio x.x.x" for the tag text, as it's not that important.

* Do a "git push" then "git push origin vx.x.x" to get it into git.

* Create the tarball.  I do "make distcheck" on Linux and make sure
  everything builds, installs, uninstalls, etc. ok.

So now we have a tarball and everything in git.  Now we have to build
on Windows, after doing a get pull to get everthing:

* rm -rf $HOME/install/Gensio

* I have a build directory lying around set up with "../configure".
  From there do "make -j<x>" then "make install DESTDIR=$HOME/install".

* rm $HOME/install/Gensio/lib/*.la

* Then run the "Inno Setup Compiler" and select gensio.iss in the
  main gensio directory.

* The output will be named "Gensio.exe" in the home directory.  Rename
  it "Gensio-x.x.x-windows.exe" and copy that to the Linux system
  where you upload everything.

Now on github, create the release and upload Gensio-x.x.x-windows.exe
and gensio-x.x.x.tar.gz as part of the release.

Now we can check homebrew on MacOS.  On a MacOS system, do:

* Do a sha256sum on the gensio-x-x-x.tar.gz file.

* vi /opt/homebrew/cd Library/Taps/homebrew/homebrew-core/Formula/g/gensio.rb
  and edit the version number and set the sha256.

* HOMEBREW_NO_INSTALL_FROM_API=1 brew reinstall --build-from-source gensio
  It should complete without error.  Well, there may be errors about being
  unable to uninstall the old version, but that's ok.  It will tell you
  how to remove it by hand.

* Do "sudo sudo brew services stop gensio" then "sudo sudo brew
  services start gensio" and test that gtlsshd works.

* Do "sudo sudo brew services stop ser2net" then "sudo sudo brew
  services start ser2net" and test that ser2net works.

If MacOS fails for some reason, you have to back everything out and
start over :(.
