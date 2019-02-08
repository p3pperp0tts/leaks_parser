# leaks_parser

Parser for data dumps Collection #1 / Collection #2-5

## Description

This python script is a parser for the latest data dumps collections #1, #2-5, Antipublic #1 and Antipublic MYR & ZABUGOR #2.

It will parse text files from data dumps and will create a sqlite database.

## How to use

The script and the empty database must be moved to the root folder where collections have been decompressed:

```
Collection #1
Collection #2
Collection #3
Collection #4
Collection #5
Antipublic MYR & ZABUGOR #2
Antipublic #1
parse2bbdd.py
leaked_credentials.sqlite
```

Each collection contains subcollections that are compressed tar.gz files, and should be decompressed too, before calling the script. For example:

```
dir F:\Collection #1

Collection  #1_BTC combos
Collection  #1_Dumps - dehashed
Collection  #1_EU combos
Collection  #1_EU combos_1
Collection  #1_Games combos
Collection  #1_Games combos_Dumps
Collection  #1_Games combos_Sharpening
Collection  #1_MAIL ACCESS combos
Collection  #1_Monetary combos
Collection  #1_NEW combo semi private_Dumps
Collection  #1_NEW combo semi private_EU combo
Collection  #1_NEW combo semi private_Private combos
...
```

Each subcollection contains the files with the credentials to be parsed:

```
dir F:\Collection  #1_BTC combos

144.txt
158.txt
151.txt
214.txt
120.txt
208.txt
205.txt
161.txt
...
```

The script will be able to parse most of these files with credentials.

When a file is correctly parsed (and credentials are added to the database), it is renamed by adding the extension .ALREADYPARSED.

The script will create three output files:

- consistences.txt -> path to files correctly imported to database
- inconsistences.txt -> path to files with unknown format that were not imported to database
- exceptions.txt -> path to files that cause exception while managing them

Most of the files are imported correctly. The files that were not imported are logged into inconsistences.txt and exceptions.txt (and, in addition, they are not renamed to *.ALREADYPARSED). Probably it is necesary to implement a custom parser for that files.

## Database format

### Tables

  - Collections
  - Subcollections
  - Credentials

### Credentials table's columns

  - collection INTEGER   -> index for Collections table
  - subcollection INTEGER -> index for Subcollections table
  - username TEXT  
  - email TEXT
  - password_plaintext TEXT
  - password_md5 TEXT
  - password_sha1 TEXT
  - password_sha256 TEXT
  - password_bcrypt TEXT
  
  

