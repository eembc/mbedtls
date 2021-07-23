#!/usr/bin/env perl


# Assumptions;
# 1. every primitive has an _init() and _free() function
# 2. a _clone(src -> dst) requires the src to exist.
# 3. every init() requires a subsequent free() 
#    - Since cloning is *dst=*src, does the clone parent require a free?

use warnings;
use strict;
use Data::Dumper;

my $mute_sha_because_inside_ecdsa = 0;

# This is updated by the primary handshake function
my $g_current_state = -1;

# This is a table of current contexts that haven't been free'd (see 1-3 above).
# k = 0xLPTR, v => substring from function /mbedtls_(type)_/ 
my %g_ctx = ();
# This is a table of cloned contexts.
# k = 0xLPTR (dst); v = 0XLPTR (src)
my %g_clones = ();
# This is an incrementing alias ID the goes up each time something is added to
# the g_context_to_alias lookup.
my $g_alias_idx = 0;
# k = 0xLPTR, v = alias (this table is constantly purged during "_free()")
my %g_context_to_alias = ();
# k = alias, v = 0xLPTR (this table remains until the very end!)
my %g_alias_to_context = ();

my $ln = 0;
while (<>) {
	++$ln;
	chomp;
	#
	# These are our special debug messages...
	#
	if (/pule:/) {
		#
		# First, based on our assumptions 1-3 above, manage the context tables
		# based on messages from _init, _free, and _clone.
		#
		if (/_init\((\S+?)\)/) {
			my $context = $1;
			if (exists($g_ctx{$context})) {
				die "ERROR: Re-initializing $context (line: $ln)\n";
			} else {
				m/mbedtls_(\S+?)[(:_]/; # extract "type"
				my $short = $1;
				$g_ctx{$context} = $short;
				$g_context_to_alias{$context} = $g_alias_idx;
				$g_alias_to_context{$g_alias_idx} = $context;
				#print "DEBUG: Alias $g_alias_idx ($1) is assigned to $context (line: $ln $_)\n";
				++$g_alias_idx;
			}
		} elsif (/_free\((\S+?)\)/) {
			my $context = $1;
			if (exists($g_ctx{$context})) {
				delete($g_ctx{$context});
				if (not exists($g_context_to_alias{$context})) {
					die "ERROR: Context $context has no alias\n";
				}
				my $alias = $g_context_to_alias{$context};
				#print "DEBUG: Alias $alias deleted from $context (line: $ln $_)\n";
				delete($g_context_to_alias{$context});
				if (exists($g_clones{$context})) {
					#print "DEBUG: Deleting a clone $context (line: $ln)\n";
					delete($g_clones{$context});
				}
			} else {
				print "ERROR: Freeing un-initialized $context (line: $ln)\n";
			}
		} elsif (/clone\((\S+) -> (\S+)\)/) {
			my ($src, $dst) = ($1, $2);
			if (not exists($g_ctx{$src})) {
				die "ERROR: Cannot clone context that does not exist $src (line: $ln)\n";
			} else {
				if (exists($g_clones{$dst})) {
					die "ERROR: Clone already exists: $dst (line: $ln)\n"
				} else {
					$g_context_to_alias{$dst} = $g_alias_idx;
					$g_alias_to_context{$g_alias_idx} = $dst;
					#print "DEBUG: Alias $g_alias_idx ($1) is assigned to cloned $dst (line: $ln $_)\n";
					++$g_alias_idx;
					m/mbedtls_(\S+?)[(:_]/; # extract "type"
					$g_ctx{$dst} = $1;
					$g_clones{$dst} = $src;
				}
			}
		} elsif (/ctr_drbg_context=(\S+) aesecbenc=(\S+)\b/) {
			my $context = $1;
			my $aes_ctx = $2;
			if (exists $g_ctx{$context}) {
			} else {
				$g_ctx{$context} = "ctr/aes/E^$2";
				$g_context_to_alias{$context} = $g_alias_idx;
				$g_alias_to_context{$g_alias_idx} = $context;
				print "DEBUG: Alias $g_alias_idx ($1) is assigned to $context (line: $ln $_)\n";
				++$g_alias_idx;
			}
			&post_primitive_event($context, "bytes", 16);
		} elsif (/block_cipher_df_context=(\S+) aesecbenc=(\S+)\b/) {
			my $context = $1;
			my $aes_ctx = $2;
			if (exists $g_ctx{$context}) {
			} else {
				$g_ctx{$context} = "bc/aes/E^$2";
				$g_context_to_alias{$context} = $g_alias_idx;
				$g_alias_to_context{$g_alias_idx} = $context;
				print "DEBUG: Alias $g_alias_idx ($1) is assigned to $context (line: $ln $_)\n";
				++$g_alias_idx;
			}
			&post_primitive_event($context, "bytes", 16);
		} elsif (/mbedtls_ctr_drbg_random_with_add_context=(\S+) aesecbenc=(\S+)\b/) {
			my $context = $1;
			my $aes_ctx = $2;
			if (exists $g_ctx{$context}) {
			} else {
				$g_ctx{$context} = "rand/aes/E^$2";
				$g_context_to_alias{$context} = $g_alias_idx;
				$g_alias_to_context{$g_alias_idx} = $context;
				print "DEBUG: Alias $g_alias_idx ($1) is assigned to $context (line: $ln $_)\n";
				++$g_alias_idx;
			}
			&post_primitive_event($context, "bytes", 16);
		}
		#
		# Now handle the individual primitives
		#
		if (/mbedtls_sha256/) {
			&process_sha256($_) if not $mute_sha_because_inside_ecdsa;
		} elsif (/mbedtls_ccm/) {
			&process_ccm($_);
		} elsif (/mbedtls_gcm/) {
			&process_gcm($_);
		} elsif (/mbedtls_aes/) {
			&process_aes($_);
		} elsif (/mbedtls_ecdh/) {
			&process_ecdh($_);
		} elsif (/mbedtls_ecdsa/) { # THIS IS BUGGED BECAUSE IT TURNS OFF SHA ON INIT & FREE!!! BUGBUG
			$mute_sha_because_inside_ecdsa = 1;
			&process_ecdsa($_);
		} elsif (/EXIT/) {
			$mute_sha_because_inside_ecdsa = 0;
		} elsif (/mbedtls_ctr_drbg_random/) {
			# already handled
		} elsif (/mbedtls_ctr_drbg_context/) {
			# already handled
		} elsif (/block_cipher_df_context/) {
			# already handled
		} else {
			if (/mbedtls_internal_aes/) {
				# we already know the AES size, so no need to track all 16B calls
			} else {
				print "WARNING: Not sure what to do with $_ (line $ln)\n";
			}
		}
	} 
	#
	# This is an MBEDTLS debug message in the handshake function. It tells us
	# the current state of the handshake so that we can figure out into which
	# state each primitive operation falls.
	#
	elsif (/client state: (\d+)/) {
		$g_current_state = $1;
	}
}

sub process_sha256 () {
	my $line = shift @_;
	if ($line =~ /update:ilen = (\d+) \((\S+)\)/) {
		my ($length, $context) = ($1, $2);
		if (exists($g_ctx{$context})) {
			&post_primitive_event($context, "bytes", $length);
		} else {
			die "Cannot add bytes to context $context";
		}
	}
}

sub process_ccm () {
	my $line = shift @_;
	if ($line =~ /ccm_star.*\((\S+)\):length = (\d+)/) {
		my ($length, $context) = ($2, $1);
		if (exists($g_ctx{$context})) {
			my $short = $g_ctx{$context};
			# paranoia: make sure enc/dec didn't switch on same context
			if ($line =~ /encrypt/ and $short !~ /E$/) {
				$g_ctx{$context} .= '/E';
			} elsif ($line =~ /decrypt/ and $short !~ /D$/) {
				$g_ctx{$context} .= '/D';
			}
			&post_primitive_event($context, "bytes", $length);
		} else {
			die "Cannot add bytes to context $context";
		}
	}
}

sub process_gcm () {
	my $line = shift @_;
	if ($line =~ /update\((\S+)\):length = (\d+).*mode = (enc|dec)/) {
		my ($length, $context) = ($2, $1);
		if (exists($g_ctx{$context})) {
			# paranoia: make sure enc/dec didn't switch on same context
			my $short = $g_ctx{$context};
			if ($line =~ /= enc/ and $short !~ /E$/) {
				$g_ctx{$context} .= '/E';
			} elsif ($line =~ /= dec/ and $short !~ /D$/) {
				$g_ctx{$context} .= '/D';
			}
			&post_primitive_event($context, "bytes", $length);
		} else {
			die "Cannot add bytes to context $context";
		}
	}
}

sub process_aes () {
	my $line = shift @_;
	if ($line =~ /\((\S+)\):size = (\d+)/) {
		my ($length, $context) = ($2, $1);
		if (exists($g_ctx{$context})) {
			# paranoia: make sure enc/dec didn't switch on same context
			my $short = $g_ctx{$context};
			if ($line =~ /enc/ and $short !~ /E$/) {
				$g_ctx{$context} .= '/E';
			} elsif ($line =~ /dec/ and $short !~ /D$/) {
				$g_ctx{$context} .= '/D';
			}
			&post_primitive_event($context, "bytes", $length);
		} else {
			die "Cannot add bytes to context $context";
		}
	}
}

sub process_ecdh () {
	my $line = shift @_;
	if ($line =~ /calc_secret\((\S+?)\)/) {
		my ($length, $context) = (1, $1);
		if (exists($g_ctx{$context})) {
			&post_primitive_event($context, "calc");
		} else {
			die "Cannot add bytes to context $context";
		}
	}
}

sub process_ecdsa () {
	my $line = shift @_;
	if ($line =~ /read_signature\((\S+?)\)/) {
		my ($length, $context) = (1, $1);
		if (exists($g_ctx{$context})) {
			&post_primitive_event($context, "read");
		} else {
			die "Cannot add bytes to context $context";
		}
	} elsif ($line =~ /write_signature\((\S+?)\)/) {
		my ($length, $context) = (1, $1);
		if (exists($g_ctx{$context})) {
			&post_primitive_event($context, "write");
		} else {
			die "Cannot add bytes to context $context";
		}
	}
}


#
# Here why try to make an ALIAS x STATE table that contains a relevant
# event for each primitive. For SHA, GCM, AES, the event is "number of bytes",
# but for ECDH and ECDSA, it is calc, read or write.
#
my %g_cross;
sub post_primitive_event () {
	my ($context, $event, @extra) = @_;
	if (not exists($g_context_to_alias{$context})) {
		die "ERROR: $context has no alias";
	}
	my $alias = $g_context_to_alias{$context};
	#print "DEBUG: posting $alias > $event ($context)\n";
	$g_cross{$alias}{'type'} = $g_ctx{$context};
	if ($event eq 'bytes') {
		my $len = $extra[0];
		if (exists($g_cross{$alias}{'state'}{$g_current_state})) {
			$g_cross{$alias}{'state'}{$g_current_state}{'event'} += $len;
		} else {
			$g_cross{$alias}{'state'}{$g_current_state}{'event'} = $len;
		}
		
	} else {
		$g_cross{$alias}{'state'}{$g_current_state}{'event'} = $event;
	}
}

#
# Alert the user if any contexts were left hanging
#

if (scalar(keys %g_clones) > 0) {
	print "WARNING: Un-freed clones:\n";
	print Dumper(\%g_clones);
}

if (scalar(keys %g_ctx) > 0) {
	print "WARNING: Un-freed contexts:\n";
	print Dumper(\%g_ctx);
}


#
# Now do a fancy print (about 200 columns wide) of each event for each
# alias at each state in the handshake.
#

# Use PERL table formatters, dude.
printf "% 5s,% 30s,% 15s:,", "alias", "type", "context";
foreach my $j (-1, 0 .. 20) {
	printf "% 5d,", $j;
}
print "\n";
foreach my $alias (sort { $a <=> $b } keys %g_cross) {
	my $entry = $g_cross{$alias};
	printf "%05d,% 30s,% 15s:,", $alias, $entry->{'type'}, $g_alias_to_context{$alias};
	foreach my $j (-1, 0 .. 20) {
		if (exists($entry->{'state'}{$j})) {
			printf "% 5s,", $entry->{'state'}{$j}{'event'};
		} else {
			printf "% 5s,", " ";
		}
	}
	print "\n";
}


# Issues I saw ...
#ERROR: Freeing un-initialized 0x7ffcc9ce1b40 (line: 2248)
#WARNING: Un-freed contexts:
#$VAR1 = {
#          '0x5654fc9a52e0' => {
