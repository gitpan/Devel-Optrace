#!perl -w
use strict;
use 5.010;

use Devel::Optrace -all;

foreach my $i(1, 2){
	print $i, "\n";
}

foreach (10){
	say;
}
