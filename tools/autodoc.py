#
# Structure AutoDocumentator for ircu.
# 26/02/2000 --Gte
#
# Creates a 'structs.html', containing HTML Table definitions
# for all structures encountered in *.h in the current directory.
#
# $Id: autodoc.py,v 1.1 2000-03-18 05:20:30 bleep Exp $

import string, fnmatch, os

def parse(filename):
	OutFile = open('structs.html', 'a')
	OutFile.write("<B><H2>"+filename+"</H2>")
	stage = 1
	try:
		IncFile = open(filename, 'r')
		line = IncFile.readline()
	
		while line != "": 
			line = string.replace(line,"\n","") # Stript out LF's.
			splitline = string.split(line, " ")
			try:
				if ((stage == 2) & (splitline[0] == "};")):
					OutFile.write("</TABLE><P>"+"\n")
					stage = 1
				if (stage == 2):
					# Begin reading member information.
					declr = string.split(string.strip(line), ";", 1)
					comment = string.replace(declr[1], "*", "")
					comment = string.replace(comment, "/", "")
	
					OutFile.write("<tr>\n")
					OutFile.write("<td WIDTH=\"22%\">"+string.strip(declr[0])+"</td>\n")
					if (declr[1][-1] == "/"):
						OutFile.write("<td WIDTH=\"78%\">"+string.strip(comment)+"</td>\n")
					else:
						# Loop until end of comment string.
						while (declr[-1] != "/"):
							line = IncFile.readline()
							line = string.replace(line,"\n","") # Stript out LF's.
							declr = string.strip(line)
							comment = comment + line
						comment = string.replace(comment, "*", "")
						comment = string.replace(comment, "/", "")
						OutFile.write("<td WIDTH=\"78%\">"+string.strip(comment)+"</td>\n")
					OutFile.write("</tr>\n")						
	
				if ((splitline[0] == "struct") & (splitline[2] == "{") & (stage == 1)):
					# We've found a "Standard" structure definition.
					OutFile.write("Structure table for: \"<B>"+splitline[1]+"</B>\"<P>\n")
					OutFile.write("<table BORDER CELLSPACING=0 CELLPADDING=2 WIDTH=\"100%\" ><tr><td VALIGN=TOP WIDTH=\"22%\"><b>Variable</b></td><td VALIGN=TOP WIDTH=\"78%\"><b>Description</b></td></tr>")
					# Now, carry on until we encounter a "};".
					stage = 2
			except IndexError:
				pass
			line = IncFile.readline()
	
		IncFile.close
		OutFile.write("<HR>")
	
	except IOError:
		print("** Error, File does not exist.")	
	OutFile.close

files = os.listdir(".")
files.sort()
for file in files:
	if (fnmatch.fnmatch(file, "*.h")):
		parse(file)
