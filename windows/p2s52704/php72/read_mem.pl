#!/usr/bin/perl
# read_mem.pl <pid> <addr_hex> <len_hex_or_dec>
my ($pid, $addr_hex, $len) = @ARGV;
my $addr = hex($addr_hex);
my $n = ($len =~ /^0x/i) ? hex($len) : $len + 0;
open(my $M, "<", "/proc/$pid/mem") or die "open: $!\n";
seek($M, $addr, 0) or die "seek(0x$addr_hex): $!\n";
my $b;
read($M, $b, $n);
printf "%s\n", unpack("H*", $b);
close $M;
