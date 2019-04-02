Fairly generic https://github.com/go-acme/lego DNS challenge provider adapter.

lego's DNS provider API requires the implementation to have a dependency on
lego's dns01 package.  That makes it less than ideal for a DNS service to
directly provide a lego-compatible DNS challenge solver.  This package solves
that challenge.
