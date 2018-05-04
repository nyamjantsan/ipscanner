# ipscanner\n
simple ip scanner (using icmp)\n
**** Монгол заавар ****\n
Тухайн холбогдсон сүлжээний хаяг маскаар сүлжээнд хостыг байгаа эсэхийг шалгах 
энгийн ip scanner програм, линук үйлдлийн системийн юникс соккет ашигласан
-----Compile хийх-----
Хамгийн эхлээд libpcap санг татна.
--- sudo apt-get install lipcap-dev---
Эх код компайл хийхдээ
gcc ipscanner.c -o ipscanner -lpcap

**** Instruction ****
using unix socket programming
----Source code compile -----
Step 1
--- sudo apt-get install lipcap-dev---
Step 2 
gcc ipscanner.c -o ipscanner -lpcap
