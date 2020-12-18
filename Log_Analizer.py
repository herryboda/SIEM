import Log_Parser

#get all source IP addresses that connecting on port 444 or 445
def specificPort(port):
    cnx, cursor = Log_Parser.connectToDB()
    query = ("SELECT DISTINCT SRC_IP, PORT FROM fwlogs WHERE PORT={}".format(port))
    cursor.execute(query)
    result = cursor.fetchall()
    cursor.close()
    cnx.close()
    if len(result) != 0:
        for line in result:     # line = [SRC_IP, PORT]
            print 'DETECTED SPECIFIC PORT ATTACK!!!\n\tfrom source IP :', line[0], '-> port :', line[1]

#port scan defined by any IP address that trying to connect another computer in more than 10 different ports
def portScan():
    cnx, cursor = Log_Parser.connectToDB()
    query = ("SELECT DISTINCT SRC_IP, DST_IP, PORT FROM fwlogs")
    cursor.execute(query)
    result = cursor.fetchall()
    cursor.close()
    cnx.close()
    dic = {}
    for line in result:     # line = [SRC_IP, DST_IP, PORT]
        if line[:2] in dic.keys():
            dic[line[:2]] += 1
        else:
            dic[line[:2]] = 1
    for key, value in dic.iteritems():      # dic = {[SRC_IP, DST_IP] : 10}
        if value >= 10:
            print 'DETECTED PORT SCAN ATTACK!!!\n\tfrom source IP :', key[0], '->', value, 'ports'

#ping sweep defined by same IP address that trying to get more than 10 different IP addresses with ping (Here it will be port 0)
def pingSweep():
    cnx, cursor = Log_Parser.connectToDB()
    query = ("SELECT DISTINCT SRC_IP, DST_IP FROM fwlogs WHERE PORT = 0")
    cursor.execute(query)
    result = cursor.fetchall()
    cursor.close()
    cnx.close()
    dic = {}
    for line in result:             # line = [SRC_IP, DST_IP]
        if line[0] in dic.keys():
            dic[line[0]] += 1
        else:
            dic[line[0]] = 1
    for key, value in dic.iteritems():      # dic = {SRC_IP : 10}
        if value >= 10:
            print 'DETECTED PING SWEEP ATTACK!!!\n\tfrom source IP :', key, '->', value, 'times'

#ping sweep defined by same IP address that trying to get more than 10 different IP addresses with ping (Here it will be port 0)
#with time differences to lower than any seconds to ping sweep conditions (more than 10 hosts in less than 10 seconds)
def pingSweepWithTime(seconds):
    cnx, cursor = Log_Parser.connectToDB()
    query = ("SELECT SRC_IP, DST_IP, DATE FROM fwlogs WHERE PORT = 0")
    cursor.execute(query)
    result = cursor.fetchall()
    cursor.close()
    cnx.close()
    dic = {}
    for line in result:                     # line = [SRC_IP, DST_IP, DATE]
        if line[0] in dic.keys():
            dic[line[0]].append(line[1:3])
        else:
            dic[line[0]] = [line[1:3]]
    for key, value in dic.iteritems():      # dic = {SRC_IP : [(DST_IP, DATE), (DST_IP, DATE)]}
        if len(value) >= 10:
            start = value[0][1]
            end = value[10][1]
            time_diff = getTimeDiffreneces(start, end)
            if int(time_diff[1]) <= seconds:
                print 'DETECTED PING SWEEP ATTACK !!!\n\t' \
                      'IP address', key, 'trying to get more than 10 different IP addresses with ping: ',\
                        len(value[0][0]), 'times in', time_diff[1], 'seconds'

#calculating time differences
def getTimeDiffreneces(start, end):
    c = end - start
    return divmod(c.days * 86400 + c.seconds, 60)
