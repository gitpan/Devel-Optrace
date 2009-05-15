#!perl -w
use strict;

use Devel::Optrace;

my %h;
$h{myself} = \%h;
p(\%h);

p(\our @ISA);
p(\%^H);

p(qr/foo/, 3.14);
