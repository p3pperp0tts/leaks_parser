import sqlite3
import sys
from validate_email import validate_email
import hashlib
import binascii
import os
import shutil

##########################################################################

class LineParser:

    @staticmethod    
    def md5(s):
        m = hashlib.md5()
        m.update(s)
        return binascii.hexlify(m.digest())

    @staticmethod    
    def sha1(s):
        m = hashlib.sha1()
        m.update(s)
        return binascii.hexlify(m.digest())

    @staticmethod    
    def sha256(s):
        m = hashlib.sha256()
        m.update(s)
        return binascii.hexlify(m.digest())

    @staticmethod
    def parsesimplelinebyseparator(s, sep, sepname):
        typ = ""
        mail = ""
        user = ""
        passwd = ""        
        if s.count(sep)==1: #and s[-1]!=sep:
            l = s.split(sep)
            if validate_email(l[0]):
                typ = "user_or_mail_%s_pass" % sepname
                user = l[0]
                mail = l[0]
            else:
                typ = "user_or_mail_%s_pass" % sepname
                user = l[0]
            passwd = l[1]
            return True, user, mail, passwd, typ
        return False, "", "", "", ""

    @staticmethod
    def ismd5(passwd):
        if len(passwd)==32:
            for e in passwd:
                if not ((ord(e)>=ord('0') and ord(e)<=ord('9')) or (ord(e)>=ord('A') and ord(e)<=ord('F')) or (ord(e)>=ord('a') and ord(e)<=ord('f'))):
                    return False
            return True
        else:
            return False

    @staticmethod
    def issha1(passwd):
        if len(passwd)==40:
            for e in passwd:
                if not ((ord(e)>=ord('0') and ord(e)<=ord('9')) or (ord(e)>=ord('A') and ord(e)<=ord('F')) or (ord(e)>=ord('a') and ord(e)<=ord('f'))):
                    return False
            return True
        else:
            return False

    @staticmethod
    def issha256(passwd):
        if len(passwd)==64:
            for e in passwd:
                if not ((ord(e)>=ord('0') and ord(e)<=ord('9')) or (ord(e)>=ord('A') and ord(e)<=ord('F')) or (ord(e)>=ord('a') and ord(e)<=ord('f'))):
                    return False
            return True
        else:
            return False

    @staticmethod
    def isbcrypt(passwd):
        if len(passwd)>50 and len(passwd)<70 and (passwd[0:4]=="$2a$" or passwd[0:4]=="$2b$" or passwd[0:4]=="$2y$"):
            return True
        return False

    @staticmethod
    def parsepasswd(passwd):
        if LineParser.ismd5(passwd):
            passwdmd5 = passwd            
            passwdsha1 = ""
            passwdsha256 = ""
            passwdbcrypt = ""
            passwd = ""
        elif LineParser.issha1(passwd):
            passwdmd5 = ""
            passwdsha1 = passwd
            passwdsha256 = ""
            passwdbcrypt = ""
            passwd = ""
        elif LineParser.issha256(passwd):
            passwdmd5 = ""
            passwdsha1 = ""
            passwdsha256 = passwd
            passwdbcrypt = ""
            passwd = ""
        elif LineParser.isbcrypt(passwd):
            passwdmd5 = ""
            passwdsha1 = ""
            passwdsha256 = ""
            passwdbcrypt = passwd
            passwd = ""
        else:
            passwdmd5 = LineParser.md5(passwd)
            passwdsha1 = LineParser.sha1(passwd)
            passwdsha256 = LineParser.sha256(passwd)
            passwdbcrypt = ""
        
        return passwd, passwdmd5, passwdsha1, passwdsha256, passwdbcrypt

    @staticmethod
    def parseline(s):
        typ = ""
        mail = ""
        user = ""
        passwd = ""
        passwdmd5 = ""
        passwdsha1 = ""
        passwdsha256 = ""
        passwdbcrypt = ""
        bvalid = False
        #case   mail@mail.com:password
        #case   username:password
        #case   mail@mail.com;password
        #case   username;password
        good, user, mail, passwd, typ = LineParser.parsesimplelinebyseparator(s, ':', "doubledots_or_dotcomma")
        if not good: good, user, mail, passwd, typ = LineParser.parsesimplelinebyseparator(s, ';', "doubledots_or_dotcomma")
        if good: bvalid = True
        if bvalid: 
            passwd, passwdmd5, passwdsha1, passwdsha256, passwdbcrypt = LineParser.parsepasswd(passwd)
            return {"type": typ, "mail": mail  , "user": user, "pass": passwd, "passmd5": passwdmd5, "passsha1": passwdsha1, "passsha256": passwdsha256, "passwdbcrypt": passwdbcrypt}

##########################################################################

class LeakParser:

    def updatecache(self):
        if self.beof: return
        if len(self.fleakcache)-self.icurcache > self.maxlinelength: return
        newread = self.fleak.read(0x1000000)
        if len(newread) < 0x1000000: self.beof = True
        self.fleakcache = self.fleakcache[self.icurcache:] + newread
        self.icurcache = 0

    def updatecurline(self):
        self.updatecache()
        for linebreak in self.linebreaks:
            try: 
                ibr = self.fleakcache.index(linebreak, self.icurcache, self.icurcache+self.maxlinelength)
                self.icurlinestart = self.icurcache
                self.icurlineend = ibr+len(linebreak)
                self.icurcache = self.icurlineend
                #print self.icurlinestart, "->", self.icurlineend, ":", self.getcurline()
                return
            except: 
                continue
        if self.beof and (len(self.fleakcache)-self.icurcache<=self.maxlinelength) and (len(self.fleakcache)-self.icurcache!=0):
            self.icurlinestart = self.icurcache
            self.icurcache = len(self.fleakcache)
            self.icurlineend = self.icurcache
            return
        self.lineerr = True

    def getcurline(self):
        return self.fleakcache[self.icurlinestart:self.icurlineend].strip()

    def setcollection(self):
        scriptdir = os.path.dirname(os.path.realpath(__file__))
        relleakpath = os.path.relpath(self.leakpath, scriptdir)
        temp = os.path.normpath(relleakpath)
        temp = temp.split(os.sep)
        self.collection = str(temp[0])
        self.subcollection = str(temp[1])
        bupdatecollections = False
        if not self.BBDDcollections.has_key(self.collection): self.addBBDDcollection(self.collection)
        if not self.BBDDsubcollections.has_key(self.subcollection): self.addBBDDsubcollection(self.subcollection)
        self.collectionid = self.BBDDcollections[self.collection]
        self.subcollectionid = self.BBDDsubcollections[self.subcollection]

    def addBBDDcollection(self, collection):
        print collection
        sql = """INSERT INTO collections(collectionname) VALUES(?)"""
        self.cursor.execute(sql, (collection,))
        self.getBBDDcollections()

    def addBBDDsubcollection(self, subcollection):
        print subcollection
        sql = """INSERT INTO subcollections(subcollectionname) VALUES(?)"""
        self.cursor.execute(sql, (subcollection,))
        self.getBBDDcollections()

    def getBBDDcollections(self):
        self.BBDDcollections = {}
        l = self.cursor.execute("SELECT * FROM collections")
        for e in l:
            self.BBDDcollections[str(e[1])] = e[0]
        self.BBDDsubcollections = {}
        l = self.cursor.execute("SELECT * FROM subcollections")
        for e in l:
            self.BBDDsubcollections[str(e[1])] = e[0]
        print self.BBDDcollections
        print self.BBDDsubcollections

    def __init__(self, leakpath):
        self.maxlinelength = 200
        self.minlinelength = 3
        self.linebreaks = ["\r\n", "\r", "\n"]
        self.BBDDcollections = {}
        self.BBDDsubcollections = {}
        self.collection = ""
        self.subcollection = ""
        self.collectionid = 0
        self.subcollectionid = 0
        self.leakpath = leakpath
        self.conn = sqlite3.connect('leaked_credentials.sqlite')
        self.conn.text_factory = str
        self.cursor = self.conn.cursor()
        self.getBBDDcollections()
        self.setcollection()
        self.fleak = open(self.leakpath, "rb")
        self.fleakcache = ""
        self.icurcache = 0
        self.icurlinestart = 0
        self.icurlineend = 0
        self.beof = False
        self.lineerr = False
        self.test_info2bbdd_counter = 0
        self.info2bbdd = self.info2bbdd_real

    def info2bbdd_test(self, info):
        if self.test_info2bbdd_counter % 20000 == 0: 
            if info: print repr(info)
        self.test_info2bbdd_counter += 1

    def info2bbdd_real(self, info):
        if self.test_info2bbdd_counter % 20000 == 0: 
            if info: print repr(info)
        self.test_info2bbdd_counter += 1
        if info:
            sql = """INSERT INTO credentials(collection, subcollection, username, email, password_plaintext, password_md5, password_sha1, password_sha256, password_bcrypt) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)"""
            self.cursor.execute(sql, (self.collectionid, self.subcollectionid, str(info["user"]), str(info["mail"]), str(info["pass"]), str(info["passmd5"]), str(info["passsha1"]), str(info["passsha256"]), str(info["passwdbcrypt"]),))

    def run(self):
        lastinconsistences = []
        binconsistence = False
        self.updatecurline()
        line1 = LineParser.parseline(self.getcurline())
        line2 = LineParser.parseline(self.getcurline())
        line3 = LineParser.parseline(self.getcurline())
        line4 = LineParser.parseline(self.getcurline())
        line5 = LineParser.parseline(self.getcurline())
        if self.lineerr or not(line1!=None and \
            line2!=None and \
            line3!=None and \
            line4!=None and \
            line5!=None and \
            line1["type"] == line2["type"] and \
            line2["type"] == line3["type"] and \
            line3["type"] == line4["type"] and \
            line4["type"] == line5["type"]):
            print "Inconsistent file by first lines"
            binconsistence = True
        if not binconsistence:
            FileLeakType = line1["type"]
            print "FileLeakType:", FileLeakType
            InconsistencesCounter = 0
            self.info2bbdd(line1)
            self.info2bbdd(line2)
            self.info2bbdd(line3)
            self.info2bbdd(line4)
            self.info2bbdd(line5)
            while not self.lineerr:
                self.updatecurline()
                line = LineParser.parseline(self.getcurline())
                if not line or line["type"]!=FileLeakType:
                    InconsistencesCounter += 1
                    lastinconsistences.append(self.getcurline())
                    if len(lastinconsistences)>10: lastinconsistences = lastinconsistences[-10:]
                    #print "CAREFUL Inconsistent line after pre-filter!!!!", self.getcurline()
                else:
                    if InconsistencesCounter: InconsistencesCounter -= 1
                if InconsistencesCounter>=10:
                    print "CAREFUL Too much Inconsistences, break!"
                    binconsistence = True
                    break
                self.info2bbdd(line)
        if binconsistence:
            f = open("inconsistences.txt", "a+b")
            f.write(self.leakpath+":::"+repr(lastinconsistences)+"\r\n")
            f.close()
        else:
            f = open("consistences.txt", "a+b")
            f.write(self.leakpath+"\r\n")
            f.close()
        self.conn.commit()


def managefile(p):
    try:
        print "Managing file:", p
        lp = LeakParser(p)
        print lp.collection
        print lp.subcollection
        lp.run()
        lp.fleak.close()
        shutil.move(p, p+".ALREADYPARSED")
    except Exception as e:
        s = p + "----" + repr(e.message) + "----" + repr(e.args) + "\r\n"
        f = open("exceptions.txt", "a+b")
        f.write(s)
        f.close()

def recurfiles(p):
    for e in os.listdir(p):
        if "NOPARSE" not in e and "ALREADYPARSED" not in e:
            if os.path.isdir(p+"/"+e):
                recurfiles(p+"/"+e)
            else:
                managefile(p+"/"+e)

#f = open("inconsistences.txt", "w+b")
#f.close()
#f = open("consistences.txt", "w+b")
#f.close()
#f = open("exceptions.txt", "w+b")
#f.close()

recurfiles(os.path.dirname(os.path.realpath(__file__)))
