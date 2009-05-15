package Devel::Optrace;

use 5.008_001;
#use strict;
#use warnings;


BEGIN{
	our $VERSION = '0.01';

	require XSLoader;
	XSLoader::load(__PACKAGE__, $VERSION);
}

our @EXPORT = qw(p);

our $DB; # tracing flags

my %bits = (
	-trace   => DOf_TRACE,
	-stack   => DOf_STACK,
	-runops  => DOf_RUNOPS,
	-noopt   => DOf_NOOPT,

	-all     => DOf_ALL,
);


sub import{
	my $class = shift;

	if($^P != 0){
		push @_, -all;
	}

	while(scalar(@_) && $_[0] =~ /^-/){
		my $opt   = shift;
		my $value = (scalar(@_) && $_[0] =~ /^[01]$/ ? shift : 1);
		$class->set($opt => $value);
	}

	#no strict 'refs';
	*{caller() . '::p'} = \&p;
	return;
}

sub set{
	my($class, $opt, $value) = @_;
	my $bit = $bits{$opt};

	unless(defined $bit){
		require Carp;
		Carp::croak(qq{Unknown option "$opt"});
	}

	if($value){
		$DB |= $bit;
	}
	else{
		$DB &= ~$bit;
	}

	return;
}


1;
__END__

=head1 NAME

Devel::Optrace - Traces opcodes which are running now

=head1 VERSION

This document describes Devel::Optrace version 0.01.

=head1 SYNOPSIS

	use Devel::Optrace;
	Devel::Optrace->set(-all => 1); # enables -trace, -stack and -runops
	# ...
	Devel::Optrace->set(-all => 0); # disables -trace, stack and -runops

	# or command line:
	# $ perl -MDevel::Optrace=-all -e '...'  # normal way
	# $ perl -d:Optrace -e '...'             # shortcut


=head1 DESCRIPTION

Devel::Optrace is an opcode debugger which traces opcodes and stacks.

There are three trace options:

=over 4

=item -trace

Traces opcodes like perl's C<-Dt>, reporting
C<"$opcode @op_private @op_flags"> or C<"$opcode(@op_data) @op_private @op_flags">.

=item -stack

Dumps the perl stack (C<PL_stack>) like perl's C<-Ds>.

=item -runops

Traces C<runops> levels.

=back

=head1 EXAMPLES

C<< perl -d:Optrace -e 'print qq{Hello, @_ world!\n}' >>:

	Entering RUNOPS (-e:0)
	()
	enter
	 ()
	 nextstate(main -e:1) VOID
	 ()
	 pushmark SCALAR
	 ()
	 const("Hello, ") SCALAR
	 ("Hello, ")
	 pushmark SCALAR
	 ("Hello, ")
	 gvsv($") SCALAR
	 ("Hello, "," ")
	 gv(*_) SCALAR
	 ("Hello, "," ",*_)
	 rv2av LIST KIDS
	 ("Hello, "," ")
	 join SCALAR KIDS
	 ("Hello, ","")
	 concat SCALAR KIDS
	 ("Hello, ")
	 const(" world!\n") SCALAR
	 ("Hello, "," world!\n")
	 concat SCALAR KIDS STACKED
	 ("Hello,  world!\n")
	 print VOID KIDS
	 (YES)
	 leave VOID KIDS PARENS
	()
	Leaving RUNOPS (-e:0)

=head1 DEPENDENCIES

Perl 5.8.1 or later, and a C compiler.

=head1 BUGS

No bugs have been reported.

Please report any bugs or feature requests to the author.

=head1 SEE ALSO

L<perlrun>.

L<B::Concise>.

=head1 AUTHOR

Goro Fuji (gfx) E<lt>gfuji(at)cpan.orgE<gt>.

=head1 LICENSE AND COPYRIGHT

Copyright (c) 2009, Goro Fuji (gfx). Some rights reserved.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
