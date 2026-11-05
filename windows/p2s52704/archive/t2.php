<?php
foreach([4,8,12,16,32,64,128] as $mb){
  $b = str_repeat(chr(65), $mb*1024*1024);
  echo $mb."M usage=".round(memory_get_usage(true)/1048576,2)." peak=".round(memory_get_peak_usage(true)/1048576,2)." ok\n";
  unset($b);
}
