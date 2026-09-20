0000000000401136 <main>:
  401136:       55                      push   %rbp
  401137:       48 89 e5                mov    %rsp,%rbp
  40113a:       48 83 ec 20             sub    $0x20,%rsp
  40113e:       48 8d 45 e0             lea    -0x20(%rbp),%rax
  401142:       48 89 c6                mov    %rax,%rsi
  401145:       48 8d 3d b8 0e 00 00    lea    0xeb8(%rip),%rdi
  40114c:       b8 00 00 00 00          mov    $0x0,%eax
  401151:       e8 da fe ff ff          call   401030 <scanf@plt>
  401156:       48 8d 45 e0             lea    -0x20(%rbp),%rax
  40115a:       48 89 c7                mov    %rax,%rdi
  40115d:       e8 ce fe ff ff          call   401040 <system@plt>
  401162:       b8 00 00 00 00          mov    $0x0,%eax
  401167:       c9                      leave
  401168:       c3                      ret

0000000000401169 <helper>:
  401169:       55                      push   %rbp
  40116a:       48 89 e5                mov    %rsp,%rbp
  40116d:       48 8d 3d 8c 0e 00 00    lea    0xe8c(%rip),%rdi
  401174:       e8 c7 fe ff ff          call   401040 <system@plt>
  401179:       90                      nop
  40117a:       5d                      pop    %rbp
  40117b:       c3                      ret

000000000040117c <safe>:
  40117c:       55                      push   %rbp
  40117d:       48 89 e5                mov    %rsp,%rbp
  401180:       48 8d 45 e0             lea    -0x20(%rbp),%rax
  401184:       48 89 c6                mov    %rax,%rsi
  401187:       e8 94 fe ff ff          call   401030 <scanf@plt>
  40118c:       48 8d 45 e0             lea    -0x20(%rbp),%rax
  401190:       48 89 c7                mov    %rax,%rdi
  401193:       e8 98 fe ff ff          call   401050 <printf@plt>
  401198:       90                      nop
  401199:       5d                      pop    %rbp
  40119a:       c3                      ret
