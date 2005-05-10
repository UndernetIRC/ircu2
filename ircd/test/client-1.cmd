define srv localhost:7701

connect cl1 Alex alex %srv% :Test client 1
connect cl2 Bubb bubb %srv% :Test client 2
:cl1 oper oper1 oper1
:cl2 wait cl1
:cl2 oper oper3 oper4
:cl2 oper oper2 oper2
:cl1 raw :privs Bubb
:cl2 raw :privs Alex Alex
sync cl1,cl2
