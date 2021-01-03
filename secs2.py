# importing required modules 
from zipfile import ZipFile # for unzipping files
import pdfplumber # the pdf extractor module
import pandas as pandadata # this is for CSV reader functionality.
import os # this is to manipulate file deletion for the last cleanup stage.
import datetime # for time stamping
  
# specifying the zip file name 
file_name = "Report.zip"
  
# # opening the zip file in READ mode 
with ZipFile(file_name, 'r') as zip: 

     zip.extractall() 

# # pdfplumber extraction
# version 2 doesn't use proxy textfile anymore, Goes directly from buffer using splitlines()

with pdfplumber.open("report.pdf") as pdf:
    first_page = pdf.pages[2]

    lineoftextfile = first_page.extract_text().splitlines()  # this makes first_page to be read line by line

    print("")

    print(lineoftextfile[1])  # this prints out the first line of the extracted data from PDF. Note that these lines are indexed from zero
    print("")

    print(lineoftextfile[3])
    print("")
    print(lineoftextfile[4])
    print("")
    print(lineoftextfile[5])
    print("")

    # Total Malware count - START

    malwarecount = lineoftextfile[10]

    print("Total Malware: " + str(malwarecount))  # data has to be converted to string, str() for printouts
    print("")

    # Total Malware - END

    # Total Spam detections - START

    blockedspam = int(lineoftextfile[9].replace(',',''))  # data has to be converted to Integer int() for arithmetic

    allowedspam = int(lineoftextfile[11])

    totalspam = blockedspam + allowedspam

    print("Total Spams Detected: " + str(totalspam))

    # Total Spam detections - END

    print("")

    # Total Phishing emails section - Start

    phishingdatablocked = lineoftextfile[14].split()  # split() is used for word by word separation
    phishdata1 = int(phishingdatablocked[0])
    
    phishingdata = lineoftextfile[15].split()
    phishdata2 = int(phishingdata[0])

    totalphishdata = phishdata2 + phishdata1

    print("Total Phishing Emails: " + str(totalphishdata))

    # Total Phishing emails section - END

    print("")

    # Total Newsletter detected - START

    taggednewsletter = lineoftextfile[14].split()

    taggednewslettersplit = int(taggednewsletter[1].replace(',',''))  # replace() is used because number data originally has a comma and not good for arithmetic

    allowednewletter = lineoftextfile[15].split()

    allowednewlettersplit = int(allowednewletter[1].replace(',',''))

    totalnewsletter = allowednewlettersplit + taggednewslettersplit

    print("Total Newsletter: " + str(totalnewsletter))

    # Total Newsletter detected - END

    print("")

    print(lineoftextfile[19])
    print("")


# for Quarantined items, we use PANDAS module. This can read CSV files. Take note that we have to use a specific encoding format i.e. 'utf_16_le'
# and specify the separator as '\t' for TAB bec the data is TAB separated and not COMMA separated.

datapanda = pandadata.read_csv('EmailAnti-SpamDetail.csv',sep='\t',encoding='utf_16_le')  # encoding used by symantec report is utf_16_le

quarantinedemails = datapanda.loc[datapanda['Action'] == 'Quarantined'].shape[0]  # from the CSV, needs to filter all rows with "Quarantined" in the Action column.

print("Total Quarantined Emails (24 Hr Period): " + str(quarantinedemails))

print("")


#cleanup section
os.remove("EmailAnti-MalwareDetail.csv")
os.remove("EmailAnti-SpamDetail.csv")
os.remove("EmailDataProtectionDetail.csv")
os.remove("EmailImageControlDetail.csv")
os.remove("EmailImpersonationControlDetail.csv")
os.remove("EmailQuarantine(ReleaseandDeleteDetail).csv")
os.remove("EmailQuarantine(ReleaseandDeleteSummary).csv")
os.remove("Report.pdf")

#Renaming Report.zip with timestamp

x = datetime.datetime.now().strftime("%m%d%Y%H%M%S")

os.rename(file_name,'Report-' + str(x) + '.zip')
