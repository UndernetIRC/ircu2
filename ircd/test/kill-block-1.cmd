define srv localhost:7701

connect cl1 Alex sub7 %srv% :s7server
connect cl2 Chloe chloe %srv% :Chloe
cl1 sleep 30
cl2 sleep 30
