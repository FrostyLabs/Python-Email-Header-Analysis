# Script:   email_analysis.py
# Desc:     extracts email addresses and IP numbers from a text file
#           or web page; for example, from a saved email header
# Author:   Oliver Thornewill von Essen
# 
#
import sys
import urllib
import re
        
def wget(url):
    '''Gets url and displays webpage content'''
    # open url like a file, based on url instead of filename
    try:
        webpage = urllib.urlopen(url)       #Open url 
        page_contents = webpage.read()      #Define page_contents by reading the webpage
        webpage.close()                     #Close file
        return page_contents 
    except:
        pass

def txtget(filename):
    '''Opens file and reads each line'''
    # open file read-only, get file contents and close
    try:
        file = open(filename, 'r')          #Open local file as read only
        file_contents = file.read()         #Define file_contents by reading the file
        file.close()                        #Close file
        return file_contents
    except:
        pass

def findIPv4(text):
    '''Search file or webpage for IP addresses'''
    ips =[]
    try:
        f = wget(text)                                                              #Gets content from webpage
        match = re.findall(r"\b\d{1,3}[0-255]\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", f)     #Finds ip address under criteria
    except:
        f =  txtget(text)                                                           #Gets content from local file
        match = re.findall(r"\b\d{1,3}[0-255]\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", f)     #Finds IP under criteria
    ips = ips + match                                                               #Adds next found IP address to create a list
    return ips
        

def findemail(text):
    '''Search file or webpage for Email Addresses'''
    emails = []
    try:
        e = wget(text)                              #Gets content from webpage
        match = re.findall(r'[\w\.-]+@[\w\.-]+', e) #Finds emails under criteria
    except:
        e = txtget(text)
        match = re.findall(r'[\w\.-]+@[\w\.-]+', e)
    match = set(match)
    match = list(match)
    emails = emails + match
    return emails



def phone_get(txt):
    '''Finds phone numbers within a webpage'''
    phone =[]
    p = wget(txt)

    match = re.findall(r"\+44\(\d\)\d{3}\s?\d{3}\s?\d{4}", p)

    match = set(match)
    match = list(match)
    phone = phone + match
    
    print '[!]', len(match),'Phone Numbers Found:'
    for i in match:
        print '    '+i
    return phone

def hash_get(txt):
    '''Find hash within a webpage'''
    pwd =[]
    h = wget(txt)

    match = re.findall(r"[\d?\w?]{32}", h)
    match = set(match)
    match = list(match)
    pwd = pwd + match
    print '[!]', len(match),'Possible Hash Passwords Found:'
    for i in match:
        print '    '+i
    return pwd

def analyse(text):
    try:
        '''Gathers Email and IP information and prints results'''
        print '[*]Analysing Content from: %s \n' % text
        #print '[*]', len(findIPv4(text)), 'IP addresses found:'
        #for i in findIPv4(text):
        #    print '    '+i
        #print '\n'
        print '[*]', len(findemail(text)), 'Email addersses found:'
        for i in findemail(text):
            print '    '+i
        print '\n'
    except:
        print 'fucked it'
    
    
    

def main():
        # temp testing url argument
    # un-comment one of the following 4 tests at a time
    #sys.argv.append('http://www.napier.ac.uk/Pages/home.aspx')
    #sys.argv.append('htp:www.broken.co')
    #sys.argv.append('http://asecuritysite.com/email01.txt')
    #sys.argv.append('http://asecuritysite.com/email02.txt')
    #sys.argv.append('C:\\temp\\ip.txt')
    #sys.argv.append(r'C:\\temp\\ips.txt')
    sys.argv.append('http://www.soc.napier.ac.uk/~40001507/CSN08115/cw_webpage/index.html')
    analyse(sys.argv[1])
    
    
    phone_get(sys.argv[1])
    print ""
    hash_get(sys.argv[1])

    #Check Args
    if len(sys.argv) != 2:
        print '[-] Usage: email_analysis URL/filename'
        return

if __name__ == '__main__':
	main()
