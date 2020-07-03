# ipscanner <br />
simple ip scanner (using icmp)<br />
**Монгол заавар** <br />
Тухайн холбогдсон сүлжээний хаяг маскаар сүлжээнд хостыг байгаа эсэхийг шалгах 
энгийн ip scanner програм, линукс үйлдлийн системийн юникс соккет ашигласан. <br />
---Compile хийх---<br />
Хамгийн эхлээд libpcap санг татна.<br />
sudo apt-get install lipcap-dev<br />
Эх код компайл хийхдээ<br />
gcc ipscanner.c -o ipscanner -lpcap<br />

**Instruction** <br />
using unix socket programming and linux pcap library<br />
---Source code compile ---<br />
Step 1<br />
sudo apt-get install lipcap-dev<br />
Step 2 <br />
gcc ipscanner.c -o ipscanner -lpcap
