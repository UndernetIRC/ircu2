define srv localhost:7701

connect cl1 Alex alex %srv% :Test client 1
:cl1 oper oper1 oper1
:cl1 raw :GET LOG
:cl1 raw :RESET LOG
:cl1 raw :GET RANDOM_SEED
:cl1 raw :SET RANDOM_SEED
:cl1 raw :SET RANDOM_SEED abcdefghijklmnop
:cl1 raw :GET DEFAULT_LIST_PARAM
:cl1 raw :SET DEFAULT_LIST_PARAM FALSE
:cl1 raw :SET DEFAULT_LIST_PARAM TRUE
:cl1 nick Alexey
:cl1 nick Amdahl
:cl1 nick Andy
:cl1 nick Aon
:cl1 nick Apple
:cl1 raw :SET NICKNAMEHISTORYLENGTH 4
