<?php
$pid = $argv[1] ?? '53';
$ms = [];
$total = 0;
foreach (file('/proc/' . $pid . '/maps') as $line) {
    $p = preg_split('/\s+/', trim($line));
    if (count($p) == 5 && $p[1] == 'rw-p') {
        list($s, $e) = explode('-', $p[0]);
        $sz = hexdec($e) - hexdec($s);
        $ms[] = [$sz, hexdec($s)];
        $total++;
    }
}
echo "total rw-p mappings: " . $total . "\n";
rsort($ms);
echo "top 12 by size:\n";
foreach (array_slice($ms, 0, 12) as [$sz, $a]) {
    printf("  size=0x%x (%dKB) start=0x%x\n", $sz, $sz >> 10, $a);
}
