#!/bin/sh
# Shared local-path volume between job pod vjob (gvisor-job) and box pod vbox (gvisor-box). Needs: $K = kubectl.
J(){ $K -n jobs exec vjob -- sh -c "$1"; }; B(){ $K -n jobs exec vbox -- sh -c "$1"; }
chk(){ if [ "$2" = "$3" ]; then echo "PASS $1"; else echo "FAIL $1: want [$3] got [$2]"; fi; }
J 'echo one > /work/f'; chk "box reads job's new file" "$(B 'cat /work/f')" "one"
B 'cat /work/f >/dev/null'; J 'echo two >> /work/f'; chk "box re-reads after job appends" "$(B 'cat /work/f | tr "\n" ,')" "one,two,"
J 'echo three > /work/f'; chk "box re-reads after job rewrites" "$(B 'cat /work/f')" "three"
B 'ls /work >/dev/null'; J 'touch /work/new1'; chk "box lists job's new file" "$(B 'ls /work | tr "\n" ,')" "f,new1,"
J 'mv /work/new1 /work/renamed'; chk "box sees job's rename" "$(B 'ls /work | tr "\n" ,')" "f,renamed,"
J 'mkdir -p /work/d && echo x > /work/d/y'; chk "box sees job's new dir" "$(B 'cat /work/d/y')" "x"
J 'cat /work/f >/dev/null'; B 'echo fromBox > /work/f'; chk "job re-reads after box rewrites" "$(J 'cat /work/f')" "fromBox"
J 'ls /work >/dev/null'; B 'mv /work/renamed /work/d/moved; touch /work/b1'; chk "job lists after box moves a file out and creates one" "$(J 'ls /work | tr "\n" ,')" "b1,d,f,"
chk "job sees the moved file at its new place" "$(J 'ls /work/d | tr "\n" ,')" "moved,y,"
J 'stat -c %s /work/f >/dev/null'; B 'head -c 5000 /dev/zero > /work/f'; chk "job sees size change by stat" "$(J 'stat -c %s /work/f')" "5000"
$K -n jobs exec vjob -- sh -c 'exec 3>>/work/log; for i in 1 2 3; do echo j$i >&3; sleep 1; done' & B 'sleep 1.5; echo b >> /work/log'; wait
chk "interleaved appends from both all present" "$(J 'wc -l < /work/log | tr -d " "')" "4"
