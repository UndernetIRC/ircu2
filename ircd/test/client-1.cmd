define srv localhost:7701

connect cl1 Alex alex %srv% :Test client 1
:cl1 oper oper1 oper1
connect cl2 Bubb bubb %srv% :Test client 2
:cl2 oper oper3 oper4
:cl2 oper oldoper wrongpass
:cl2 oper md5oper wrongpass
:cl2 oper cryptoper wrongpass
:cl2 oper oper2 oper2
:cl2 raw :privs Alex Alex
:cl1 wait cl2
:cl1 raw :privs Bubb
:cl1 nick A
:cl1 nick Alexey
