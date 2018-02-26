PVA: Dynamic Packet Forwarding Verification in SDN
====================================

PVA is desinged as a SDN application, which levarages the flexitibily and fine-grained controlability of SDN, to perform forwarding path verification for detecting traffic hijack. It picks forwarding packets and tracks them down along the path to see whether those traces yield to network policy. PVA uses a ramdom sampling scheme to keep balance between overhead and accuracy. We implement its prototype on an opensource SDN controller, [Floodlight](http://www.projectfloodlight.org/floodlight/).

Publication
====================================

PVA is a research project, and it is conducted in the [Internet and Cloud Security Research Group](http://ics.netlab.edu.cn/). Our paper is recently accepted by [IEEE TDSC](https://www.computer.org/web/tdsc) and will appear soon.