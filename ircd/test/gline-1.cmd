define srv localhost:7701

connect cl1 Alex alex %srv% :Test client 1
:cl1 oper oper1 oper1
:cl1 raw :gline !+$Rbubb 30 :Bubb is not welcome here
:cl1 sleep 35
:cl1 raw :gline !+127.2.* 3600 :Localclone?
:cl1 sleep 5
:cl1 raw :gline !+127.2.* 3600 :Localclone?
:cl1 raw :gline !+127.2.*/15 3600 :Localclone?
:cl1 raw :gline !+127.2.0.0/33 3600 :Localclone?
:cl1 raw :gline !+127.2.0.0/15 3600 :Localclone?
connect cl2 Bubb bubb %srv% :Test client 2
:cl1 raw :gline
:cl1 raw :gline $Rbubb
:cl1 raw :gline -$Rbubb
:cl1 wait cl2
:cl1 raw :gline !+$Rbubb * 3600 :Bubb is not welcome here
:cl1 sleep 5
:cl1 raw :gline -$Rbubb
:cl1 raw :gline +#warez 30 :Warez r bad mmkay
:cl2 wait cl1
:cl2 join #warez
:cl1 sleep 35
:cl1 raw :stats glines
:cl1 raw :gline !+*@127.0.0.2 3600 :Localclone?
:cl1 raw :gline !+127.1.* 3600 :Localclone?
:cl1 raw :stats memory
:cl2 raw :gline
