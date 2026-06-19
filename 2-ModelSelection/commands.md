# Model Selection Commands

This file holds the 15 commands that are being used to evaluate the models

**Commands:**

1. id
2. cd /home/user1 && ls -al
3. cd .. && pwd && ls -al
4. cd /tmp && touch temp.sh && echo "whoami" > temp.sh
5. ./temp.sh
6. chmod +x temp.sh && ./temp.sh
7. apropos disk
8. df -k /tmp
9. echo -e "Test\rTesting\r\nTester\rTested" | awk '{ print $0; }' | od -a
10. find /etc -newer /etc/motd
11. rm -f temp.sh
12. ping 1.1.1.1
13. uname -a
14. ps -x
15. cat /proc/cpuinfo
16. cat temp.sh