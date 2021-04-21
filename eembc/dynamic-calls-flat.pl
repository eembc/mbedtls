#!/usr/bin/env perl
use warnings;
use strict;
$|=1;

my $objects = $ARGV[0];
my $traceout = $ARGV[1];

die "Missing objects file" if not $objects or not -f $objects;
die "Missing traceout file" if not $traceout or not -f $traceout;

my %addr2f;

my $fp;

open($fp, "<$traceout");
$_ = <$fp>;
close $fp;
my @parts = split;
my $main_base = $parts[1];
# Perl can't handle large addresses but we stay in largepage
# so just take last 8 hex digits as (32b) address
print "$main_base\n";
$main_base =~ m/(\S{8})$/;
$main_base = hex($1);
printf("%x\n", $main_base);


my $main_offset;
open($fp, "<$objects");
while (<$fp>) {
	if (/^(\S+) \<(\S+?)\>:/i) {
		if ($2 eq "main") {
			$main_offset = $1;
			#$main_offset =~ m/(\S{8})$/;
			$main_offset = hex($1);
		}
	}
}
close $fp;

printf("Main offset %x\n", $main_offset);

my $offset = $main_base - $main_offset;

printf("Final offset %x\n", $offset);

open($fp, "<$objects");
while (<$fp>) {
	if (/^(\S+) \<(\S+?)\>:/i) {
		my ($addr, $name) =($1, $2);
#		my $key = sprintf("%x", $offset + hex($addr));
		my $key = sprintf("%x", hex($addr));
		$addr2f{$key} = $name;
	}
}
close $fp;

open($fp, "<$traceout");
my $depth = 0;
my $tabs = '';
my $callnum = 0;
my @stack = ();
while (<$fp>) {
	++$callnum;
	my ($dir, $faddr, $caddr, $time) = split;
	my $faddrorg = $faddr;
	$faddr =~ m/(\S{8})$/;
	$faddr = sprintf("%x", hex($1));
	my $fname = $addr2f{$faddr};

	print("Unknown: $faddrorg $faddr\n") if not $fname;
	$fname = "??" if not $fname;
	if ($dir eq 'e') {
		push @stack, $fname;
		printf("%08d %s %s\n", $callnum++, $faddrorg, join(":", @stack));
	} else {
		pop @stack;
	}
}
close $fp;

