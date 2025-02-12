So you want to help with gensio.  Well, that's a fine thing, please
do.  Here are some things you can do:

* Report bugs.  See SECURITY.md for bugs that might be security
  sensitive.  Use the normal github bug reporting from the github page
  (https://github.com/cminyard/gensio) for other bugs.

* Write documentation.  The world needs good documentation.  I've
  tried, but I'm only one person.

* Ask for new features.  Obviously, bugs take precedence over new
  features, but cool ideas are accepted.  Of course, source to
  implement those features is even better, so...

* Write code for gensio.  Write your own gensio, or add features to
  existing ones.  Bug fixes.  Examples.

=======================
Code Contribution Rules
=======================

All contributions must be signed of with a "Signed-off-by:" line
following the Developer Certificate of Origin.  See
https://developercertificate.org.

Please follow the coding style of the existing code.  It's basically
Linux kernel style with 4-character indent.

Submit fixes, documentation updates, and new features through github
pull requests.

New gensios that go into the main library must be LGPL-2.1.

If you add a new gensio or feature, you must add a test for it.

If you make any changes, the changed code must pass all tests.  See
"Running Tests" in the README.rst file.
