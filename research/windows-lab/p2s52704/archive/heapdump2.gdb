set pagination off
set confirm off
set width 0
set $R = *(unsigned long*)0x77cf71cdf3e0
print/x $R
echo === R-0x80 .. R+0x80 ===\nx/40gx $R-0x80
echo === R struct ===\nx/4gx $R
echo ---END---\n