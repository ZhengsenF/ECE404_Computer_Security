from TcpAttack import *
spoofIP = '192.128.0.1'
targetIP = '198.232.120.146'

Tcp = TcpAttack(spoofIP, targetIP)
Tcp.scanTarget(1995, 2005)
# if Tcp.attackTarget(2000, 10):
#     print('open')
# else:
#     print('not open')

