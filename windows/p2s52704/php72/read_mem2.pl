#!/usr/bin/perl
# read_mem2.pl <pid> <addr_hex> <len>  (prints read count + error)
my ($pid, $addr_hex, $len) = @ARGV;
my $addr = hex($addr_hex);
my $n = ($len =~ /^0x/i) ? hex($len) : $len + 0;
my $fh;
open($fh, "<", "/proc/$pid/mem") or do { print "OPEN FAIL: $!\n"; exit 1; };
my $ok = seek($fh, $addr, 0);
my $b;
my $r = ($ok ? read($fh, $b, $n) : 0);
if ($r) {
    printf "READ OK %d bytes: %s\n", $r, unpack("H*", $b);
} else {
    printf "READ FAIL at 0x%s (seek=%s): %s\n", $addr_hex, ($ok?"ok":"$!"), ($!||"read returned 0");
}
close $fh;
