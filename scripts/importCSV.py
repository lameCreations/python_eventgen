import csv
import datetime
import time
import random
import string

class meta_ids(object):
        def __init__(self, id, scenarioName, scenarioTime, site):
             self.id = id
             self.scenarioName = scenarioName
             self.scenarioTime = scenarioTime
             self.site = site

class inventory_item(object):
        def __init__(self, site, location, ip, hostname, mac, model, os, vendor, role):
             self.site = site
             self.location = location
             self.ip = ip
             self.hostname = hostname
             self.mac = mac
             self.model = model
             self.os = os
             self.vendor = vendor
             self.role = role

class ids_alert(object):
        def __init__(self, scenario_id, logName, src_ip, src_port, dest_ip, dest_port, proto, service, bytes_seen, bytes_out, timeModifier, userAgent, scanInternal, scanDMZ, alertName, success, answer, value, referrer, ids_id, intel_source, query, intel_tag, description, first_seen, indicator_type, mime_type, file_description):
            self.scenario_id = scenario_id
            self.logName = logName
            self.src_ip = src_ip
            self.src_port = src_port
            self.dest_ip = dest_ip
            self.dest_port = dest_port
            self.proto = proto
            self.service = service 
            self.bytes_seen = bytes_seen 
            self.bytes_out = bytes_out
            self.timeModifier = timeModifier
            self.userAgent = userAgent
            self.scanInternal = scanInternal
            self.scanDMZ = scanDMZ
            self.alertName = alertName
            self.success = success
            self.answer = answer
            self.value = value
            self.referrer = referrer
            self.ids_id = ids_id 
            self.intel_source = intel_source
            self.query = query
            self.intel_tag = intel_tag
            self.description = description
            self.first_seen = first_seen
            self.indicator_type = indicator_type
            self.mime_type = mime_type
            self.file_description = file_description

def append_text_to_file(file_path, text):
    with open(file_path, 'a') as file:
        file.write(text)
        file.write('\n')
     
def read_csv_file(file_path)->list:
    data = []
    with open(file_path, 'r') as csv_file:
        csv_reader = csv.reader(csv_file)
        for row in csv_reader:
            data.append(row)
    return data

def generate_uid():
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(characters) for _ in range(9))
    return random_string

def Write_All_Scenario():
   
    for nMeta in ListOfMetaIDS:
        uid = generate_uid()
        for nIDS in ListOfIdS_Alerts:
            if nMeta.id == nIDS.scenario_id:
                if nIDS.logName == 'ping_scan':
                    internalScanVariable = 'false'
                    dmzScanVariable = 'false'
                    if nIDS.scanInternal == "True":
                        internalScanVariable = "true"                    
                    else:
                        internalScanVariable == 'false'
                    if nIDS.scanDMZ == "True":
                        dmzScanVariable = 'true'
                    else:
                        dmzScanVariable = 'false'
            
                    if nIDS.dest_port == 0:
                        createPingScan(nIDS.src_ip, nIDS.dest_ip, nIDS.src_port, nIDS.dest_port, nIDS.scanInternal, nIDS.scanDMZ, nIDS.proto, nIDS.service, nIDS.timeModifier)                    

                    else:
                        createPingScan(nIDS.src_ip, nIDS.dest_ip, nIDS.src_port, nIDS.dest_port, nIDS.scanInternal, nIDS.scanDMZ, nIDS.proto, nIDS.service, nIDS.timeModifier)                    
                
                elif nIDS.logName == 'bacnet':
                    current_time = int(time.time())
                    writeBacnetLog("site1", nIDS.src_port, nIDS.dest_port, nIDS.src_ip, nIDS.dest_ip, uid, current_time, nIDS.value)      

                elif nIDS.logName == 'corelight_conn':
                    #print("hello")
                    current_time = int(time.time())
                    writeConnLog("site1", nIDS.src_port, nIDS.dest_port, nIDS.src_ip, nIDS.dest_ip, 0,0, nIDS.proto, nIDS.service, "ShADadFf", "SF", uid, time.time())
                
                elif nIDS.logName == 'corelight_rdp':
                    #print("RDP_Log")
                    current_time = int(time.time())
            
                    if nIDS.success == "no":
                        #print("hello")
                
                        writeRDPLog("site1", "failure", nIDS.src_port, nIDS.dest_port, nIDS.src_ip, nIDS.dest_ip, uid, current_time) 
                    
                    else:
                        writeRDPLog("site1", "success", nIDS.src_port, nIDS.dest_port, nIDS.src_ip, nIDS.dest_ip, uid, current_time) 
                
                elif nIDS.logName == 'estreamer':
                    #print("estreamer Logs")
                    current_time = int(time.time())
            
                    writeEstreamer(current_time, uid, nIDS.src_port, nIDS.dest_port, nIDS.src_ip, nIDS.dest_ip, "SERVER-OTHER Apahce Log4j logging remote code execution attempt", "58737", "Attempted User Privilege Gain")
               
                elif nIDS.logName == 'corelight_http':
                    print("http log")
                    current_time = int(time.time())
                    writeHTTPLog("site1", nIDS.src_port, nIDS.dest_port, nIDS.src_ip, nIDS.dest_ip, 0, 0, "n/a", uid, 200, "Get", "n/a", "n/a", "n/a", nIDS.userAgent, time.time() )
           
                elif nIDS.logName == 'corelight_tds':
                    #print("SQL Log")
                    current_time = int(time.time())
                    writeSQLServerLog("site1", nIDS.src_port, nIDS.dest_port, nIDS.src_ip, nIDS.dest_ip, uid, current_time, nIDS.alertName)
    
                elif nIDS.logName == 'corelight_notice':
                    #print("notice log")
                    current_time = int(time.time())
                    writeCorelightNotice()

                elif nIDS.logName == 'corelight_dns':
                    #print("DNS Log")
                    current_time = int(time.time())
            
                    writeDNSLog(nIDS.src_port, nIDS.dest_port, nIDS.src_ip, nIDS.dest_ip, uid, nIDS.query, nIDS.answer, time.time())
              
                elif nIDS.logName == 'corelight_intel':
                    #print("Intel Log")
                    current_time = int(time.time())
                    writeIntel(nIDS.mime_type, nIDS.description, nIDS.bytes_seen, nIDS.service, nIDS.bytes_out, uid, "c123", nIDS.answer, nIDS.src_ip, nIDS.dest_ip, nIDS.dest_port, nIDS.src_port, current_time)
                    # writeIntel(mime_type, description, indicatorType, indicatorSeen, intelSource, intelTags, firstSeen, uid, fuid, indicator, src_ip, dest_ip, dest_port, src_port, the_time):

def Write_Custom_Scenario(id, scenarioName, scenarioTime):
    #print("Hello World")

    for nIDS in ListOfIdS_Alerts:
        print(nIDS.logName)
        uid = generate_uid()
        if nIDS.logName == 'ping_scan':
            print("Ping Scan")
            internalScanVariable = 'false'
            dmzScanVariable = 'false'
            if nIDS.scanInternal == "True":
                internalScanVariable = "true"                    
            else:
                internalScanVariable == 'false'
            if nIDS.scanDMZ == "True":
                dmzScanVariable = 'true'
            else:
                dmzScanVariable = 'false'
            
            if nIDS.dest_port == 0:
                createPingScan(nIDS.src_ip, nIDS.dest_ip, nIDS.src_port, nIDS.dest_port, nIDS.scanInternal, nIDS.scanDMZ, nIDS.proto, nIDS.service, nIDS.timeModifier)                    

            else:
                createPingScan(nIDS.src_ip, nIDS.dest_ip, nIDS.src_port, nIDS.dest_port, nIDS.scanInternal, nIDS.scanDMZ, nIDS.proto, nIDS.service, nIDS.timeModifier)                    
        elif nIDS.logName == 'corelight_rdp':
            print("RDP_Log")
            current_time = int(time.time())
            #uid = generate_uid
            if nIDS.success == "True":
                print("hello")
                
                writeRDPLog("site1", "True", nIDS.src_port, nIDS.dest_port, nIDS.src_ip, nIDS.dest_ip, uid, current_time) 
                writeRDPLog("site1", "True", nIDS.src_port, nIDS.dest_port, nIDS.src_ip, nIDS.dest_ip, uid, current_time)
            else:
                writeRDPLog("site1", "False", nIDS.src_port, nIDS.dest_port, nIDS.src_ip, nIDS.dest_ip, uid, current_time) 
        elif nIDS.logName == 'estreamer':
            print("estreamer Logs")
            current_time = int(time.time())
           
            writeEstreamer(current_time, uid, nIDS.src_port, nIDS.dest_port, nIDS.src_ip, nIDS.dest_ip, "SERVER-OTHER Apahce Log4j logging remote code execution attempt", "1234", "Attempted User Privilege Gain")
        elif nIDS.logName == 'corelight_http':
            print("http log")
            current_time = int(time.time())
            writeHTTPLog("site1", nIDS.src_port, nIDS.dest_port, nIDS.src_ip, nIDS.dest_ip, 0, 0, "n/a", uid, 200, "Get", "n/a", "n/a", "n/a", nIDS.userAgent, time.time() )
        elif nIDS.logName == 'bacnet':
            current_time = int(time.time())
            writeBacnetLog("site1", nIDS.src_port, nIDS.dest_port, nIDS.src_ip, nIDS.dest_ip, uid, current_time, nIDS.value)       
        elif nIDS.logName == 'corelight_tds':
            #print("SQL Log")
            current_time = int(time.time())
            writeSQLServerLog("site1", nIDS.src_port, nIDS.dest_port, nIDS.src_ip, nIDS.dest_ip, uid, current_time, nIDS.query)
        

        elif nIDS.logName == 'corelight_notice':
            #print("notice log")
            current_time = int(time.time())
            writeCorelightNotice()

        elif nIDS.logName == 'corelight_dns':
            #print("DNS Log")
            current_time = int(time.time())
            
            writeDNSLog(nIDS.src_port, nIDS.dest_port, nIDS.src_ip, nIDS.dest_ip, uid, nIDS.query, nIDS.answer, time.time())
              
        elif nIDS.logName == 'corelight_intel':
            #print("Intel Log")
            current_time = int(time.time())
            writeIntel(nIDS.mime_type, nIDS.description, nIDS.bytes_seen, nIDS.service, nIDS.bytes_out, uid, "c123", nIDS.answer, nIDS.src_ip, nIDS.dest_ip, nIDS.dest_port, nIDS.src_port, current_time)
            # writeIntel(mime_type, description, indicatorType, indicatorSeen, intelSource, intelTags, firstSeen, uid, fuid, indicator, src_ip, dest_ip, dest_port, src_port, the_time):

def getRandomNumber(start, end):
    return random.randint(start,end)

def GenerateInventory():
    #print("Generating Inventory")
    for nInventory in ListOfInventory:
        if nInventory.role == "scanner":
            InternalScanner.append(nInventory)
        elif nInventory.role == "internal":
            InternalScanner.append(nInventory)
        elif nInventory.role == "dmz":
            DMZAddresses.append(nInventory)
        elif nInventory.role == "external":
            ExternalAddresses.append(nInventory)    

def writeBacnetLog(randHost, src_port, dest_port, src_ip, dest_ip, uid, the_time, bacnet_value):
    print("writing bacnet")
    print("writing bacnet")
    print("writing bacnet")
    logFormat = '{"ts":"' + str(the_time) + '","site":"' + str(randHost) + '","uid":"' + str(uid) + '","id.orig_h":"' + src_ip + '","id.orig_p":'+ str(src_port) +',"id.resp_h":"' + dest_ip + '","id.resp_p":' + str(dest_port) + ',"pdu_type":"' + bacnet_value + '"}'
    conn_log_path = file_output_path + "bacnet_log.txt"
    #conn_log_path = "c:/Users/palin/OneDrive/Desktop/python_scripts/sql_log.txt"
    append_text_to_file(conn_log_path, logFormat)

def writeHTTPEvent(randHost):
    #print("writing http event")
    src_ip_int = getRandomNumber(0, InternalAddressCount)
    src_ip = ListOfInventory[int(src_ip_int)].ip
    rand_src_port = getRandomNumber(1024,65532)
    rand_dest_port = 80

    while True:
        #dest_ip_int = getRandomNumber(0, ListOfInventory.count)
        dest_ip_int = getRandomNumber(0, InternalAddressCount)
        if dest_ip_int != src_ip_int:
            break
    dest_ip = ListOfInventory[int(dest_ip_int)].ip
    uid = generate_uid()

   
    writeConnLog(randHost, rand_src_port, rand_dest_port, src_ip, dest_ip, 0,0,"tcp", "http", "ShADadFf", "SF", uid, time.time())
    writeHTTPLog(randHost, rand_src_port, rand_dest_port, src_ip, dest_ip, 0, 0, "n/a", uid, 200, "Get", "n/a", "n/a", "n/a", "n/a", time.time())
    writeFilesLog(randHost, src_ip, dest_ip, 0, 0, uid, "txt", "abc123", time.time(), "fuidID")

def writeStandaloneConnLog(randHost):
    #print("Standalone Conn log")
    randConnectionType = getRandomNumber(1,3)
    dest_ip = ""
    src_ip = ""
    s_int = False
    d_int = False

    if randConnectionType == 1:
        #internal to internal
        s_int = True
        d_int = True
        intMax = InternalAddressCount
        randOne = getRandomNumber(0,int(intMax))
        randTwo = 0

        while True:
            randTwo = getRandomNumber(0, int(intMax))
            if randTwo != randOne:
                break
            
        src_ip = ListOfInventory[int(randOne)].ip
        dest_ip = ListOfInventory[int(randTwo)].ip

    elif randConnectionType == 2:
        #internal to external
        s_int = True
        d_int = True
        internalMax = InternalAddressCount
        externalMax = ExternalAddressCount
        src_ip = ListOfInventory[int(getRandomNumber(0,InternalAddressCount))].ip
        #NEED FIXED need a list of internal and external IPs
        dest_ip = ListOfInventory[int(getRandomNumber(0,InternalAddressCount))].ip
    
    elif randConnectionType == 3:
        s_int = False
        d_int = False
        internalMax = InternalAddressCount
        externalMax = ExternalAddressCount

        src_ip = ListOfInventory[int(getRandomNumber(0,InternalAddressCount))].ip
        #NEED FIXED need a list of internal and external IPs
        dest_ip = ListOfInventory[int(getRandomNumber(0,InternalAddressCount))].ip

    src_port = getRandomNumber(1024,65532)
    dest_port = getRandomNumber(1,1024)
    uid = generate_uid()
    service = "none"
    proto = ""
    proto_random = getRandomNumber(1,3)
    if proto_random == 1:
        proto = "icmp"
        src_port = 8
        dest_port = 3
    elif proto_random == 2:
        proto = "tcp"
    else:
        proto = "udp"

    #print("Sending to Conn Log Random")
    writeConnLogRandom(randHost, src_port, dest_port, src_ip, dest_ip, s_int, d_int, proto, service, "ShADadFf", "SF", uid, time.time())
    
def CreateSShEvent(randHost):
    #print("creating SSH Event")
    max = InternalAddressCount
    src_ip_rand = getRandomNumber(0,int(max))
    dest_ip = 0
    src_port = getRandomNumber(0,65532)
    dest_port = 22

    src_ip = ListOfInventory[int(src_ip_rand)].ip
        #NEED FIXED need a list of internal and external IPs
    

    authenticationOutcome = True

    while True:
        dest_ip_rand = getRandomNumber(0, int(max))
        if dest_ip_rand != src_ip_rand:
            break
    dest_ip = ListOfInventory[int(dest_ip_rand)].ip

    uid = generate_uid()
    authSuccessNumber = getRandomNumber(1,20)
    if authSuccessNumber >=19:
        authenticationOutcome = False
    else:
        authenticationOutcome = True

    writeConnLog(randHost, src_port, dest_port, src_ip, dest_ip, 0, 0, "tcp", "ssh", "n/a", "n/a", uid, time.time() )
    writeSSHLog(randHost, src_port, dest_port, src_ip, dest_ip, authenticationOutcome, uid, time.time())

    #Write-ConnLog -s_port $src_port -d_port $dest_port -s_ip $InternalAddresses[$src_ip].IP $src_ip -d_ip $InternalAddresses[$dest_ip].IP -corelight_id $uid -s_int $true -d_int $true -proto "tcp" -service "ssh" -conn_state "SF" -history "ShDTAaftFR"
    #Write-SSHLog -s_port $src_port -d_port $dest_port -s_ip $InternalAddresses[$src_ip].IP -d_ip $InternalAddresses[$dest_ip].IP -corelight_id $uid

def CreateMicrosoftSQLEvent(randHost):
    #print("Making SQL Event")
    max = InternalAddressCount
    src_ip_int = getRandomNumber(0, InternalAddressCount)
    src_ip = ListOfInventory[int(src_ip_int)].ip

    dest_ip = 0
    src_port = getRandomNumber(0,65532)
    dest_port = 1433

    while True:
        dest_ip_int = getRandomNumber(0, int(max))
        if dest_ip_int != src_ip_int:
            break
    dest_ip = ListOfInventory[int(dest_ip_int)].ip
    uid = generate_uid()

    writeConnLog(randHost, src_port, dest_port, src_ip, dest_ip, 0, 0, "tcp", "sql", "n/a", "n/a", uid, time.time())
    writeSQLServerLog(randHost, src_port, dest_port, src_ip, dest_ip, uid, time.time(), "SELECT * FROM Users WHERE UserId = 105 OR 1=1")
   
    #Write-ConnLog -s_port $src_port -d_port $dest_port -s_ip $InternalAddresses[$src_ip].IP -d_ip $InternalAddresses[$dest_ip].IP -corelight_id $uid -s_int $false -d_int $true -proto "tcp" -service "tds" -conn_state "SF" -history "ShDTAaftFR"  
    #Write_Microsoft_SQL_Log -s_port $src_port -d_port $dest_port -src_ip $InternalAddresses[$src_ip].IP -dest_ip $InternalAddresses[$dest_ip].IP -corelight_id $uid

def CreateVPNEvent(randHost):
    #print("creating VPN EVent")
    max = InternalAddressCount
    src_ip_int = getRandomNumber(0, InternalAddressCount)
    src_ip = ListOfInventory[int(src_ip_int)].ip
    dest_ip = 0
    src_port = getRandomNumber(0,65532)
    dest_port = 1190

    while True:
        dest_ip_int = getRandomNumber(0, int(max))
        if dest_ip_int != src_ip_int:
            break
    dest_ip = ListOfInventory[int(dest_ip_int)].ip     
    uid = generate_uid()

    writeConnLog(randHost, src_port, dest_port, src_ip, dest_ip, 0, 0, "tcp", "vpn", "n/a", "n/a", uid, time.time())
    writeVPNLog(randHost, src_port, dest_port, src_ip, dest_ip, time.time(), uid)
   
    #Write-ConnLog -s_port $src_port -d_port $dest_port -s_ip $InternalAddresses[$src_ip].IP -d_ip $InternalAddresses[$dest_ip].IP -corelight_id $uid -s_int $false -d_int $true -proto "tcp" -service "vpn" -conn_state "SF" -history "ShDTAaftFR"
    #Write_VPNLog -s_port $src_port -d_port $dest_port -src_ip $InternalAddresses[$src_ip].IP -dest_ip $InternalAddresses[$dest_ip].IP -corelight_id $uid

def createRDPEvent(randHost):
    #print("Create RDP Event")
    max = InternalAddressCount
    src_ip_int = getRandomNumber(0, InternalAddressCount)
    src_ip = ListOfInventory[int(src_ip_int)].ip
    dest_ip = 0
    src_port = getRandomNumber(0,65532)
    dest_port = 3389

    while True:
        dest_ip_int = getRandomNumber(0, int(max))
        if dest_ip_int != src_ip_int:
            break
    dest_ip = ListOfInventory[int(dest_ip_int)].ip

    uid = generate_uid()

    writeConnLog(randHost, src_port, dest_port, src_ip, dest_ip, 0, 0, "tcp", "rdp", "n/a", "n/a", uid, time.time())
    writeRDPLog(randHost, "success", src_port, dest_port, src_ip, dest_ip, uid, time.time())

    #Write-ConnLog -s_port $src_port -d_port $dest_port -s_ip $InternalAddresses[$src_ip_index].IP -d_ip $InternalAddresses[$dest_ip_index].IP -corelight_id $uid -s_int $true -d_int $true -proto "tcp" -service "rdp" -conn_state "SF" -history "ShDTAaftFR"
    #Write-RDPLog -s_port $src_port -d_port $dest_port -s_ip $InternalAddresses[$src_ip_index].IP -d_ip $InternalAddresses[$dest_ip_index].IP -corelight_id $uid

def writeVPNLog(randHost, s_port, d_port, src_ip, dest_ip, the_time, uid):
    #print("Writing VPN Log")

    logFormat = '{"ts":"' + str(the_time) + '","site":"' + str(randHost) + '","uid":"' + uid + '","id.orig_h":"' + src_ip + '","id.orig_p":'+ str(s_port) +',"id.resp_h":"' + dest_ip + '","id.resp_p":' + str(d_port) + ',"proto":"udp","vpn_type":"VPNInsights::OpenVPN","service":"spicy_openvpn_udp","inferences":["NSP"],"duration":31.806941032,"orig_bytes":671,"resp_bytes":10096}'
    conn_log_path = file_output_path + "vpn_log.txt"
    #conn_log_path = "c:/Users/palin/OneDrive/Desktop/python_scripts/vpn_log.txt"
    append_text_to_file(conn_log_path, logFormat)

def writeSSHLog(randHost, src_port, dest_port, src_ip, dest_ip, authSuccess, uid, the_time):
    #print("Writing SSH Log")

    #logFormat = '{"ts":"' + str(the_time) + '","uid":"' + uid + '","id.orig_h":"' + src_ip + '","id.orig_p":"' + str(src_port) + '","id.resp_h":"' + dest_ip + '","id.resp_p":"' + str(dest_port) + '","auth_success":"'+ authSuccess +'","auth_attempts":"'+ authSuccess +'","direction":"INBOUND","client":"GET / HTTP/1.1","server":"SSH-2.0-OpenSSH_6.4","inferences":["SV"]}'
    logFormat = '{"ts":"' + str(the_time) + '","site":"' + str(randHost) + '","uid":"' + uid + '","id.orig_h":"' + src_ip + '","id.orig_p":"' + str(src_port) + '","id.resp_h":"' + dest_ip + '","id.resp_p":"' + str(dest_port) + '","auth_success":"'+ str(authSuccess) +'","auth_attempts":"1","direction":"INBOUND","client":"GET / HTTP/1.1","server":"SSH-2.0-OpenSSH_6.4","inferences":["SV"]}'
      
    conn_log_path = file_output_path + "ssh_log.txt"
    #conn_log_path = "c:/Users/palin/OneDrive/Desktop/python_scripts/ssh_log.txt"
    append_text_to_file(conn_log_path, logFormat)

def GenerateRandomLogs():
    runTime = ""
    timeEnd = addTime(3600)
    timeNow = time.time()

    while True:
        timeNow = time.time()
        randEvent = getRandomNumber(1, 90)

        if randEvent >= 1 and randEvent < 40:
            writeStandaloneConnLog() 
        elif randEvent >= 39 and randEvent < 50:
            print("something")
        elif randEvent >= 49 and randEvent < 60:
            CreateVPNEvent()
        elif randEvent >= 59 and randEvent < 70:
            writeHTTPEvent()
        elif randEvent >= 69 and randEvent < 80:
            CreateSShEvent()
        elif randEvent >= 79 and randEvent < 90:
            createRDPEvent()
        elif randEvent >= 89 and randEvent < 100:
            CreateMicrosoftSQLEvent()


        if timeNow >= timeEnd:
            break


    
        #start-sleep -seconds .5

def writeConnLogRandom(randHost, src_port, dest_port, src_ip, dest_ip, s_int, d_int, proto, service, history, conn_state, uid, the_time):
    #print("writing random conn log")
    
    proto = str.upper(proto)
    bytes_in = getRandomNumber(0, 148000)
    ip_bytes_in = bytes_in * 1.65
    pkts_in = getRandomNumber(0, 140)
    bytes_out = getRandomNumber(49, 16805)
    ip_bytes_out = bytes_out * 1.75
    pkts_out = getRandomNumber(1,81)

    logFormat = '{"ts":"' + str(the_time) + '","site":"' + str(randHost) + '","uid":"' + str(uid) + '","id.orig_h":"' + src_ip + '","id.orig_p":"'+ str(src_port) +'","id.resp_h":"' + dest_ip + '","id.resp_p":"' + str(dest_port) + '","proto":"' + proto + '","service":"'+ service + '","conn_state":"' + conn_state + '","local_orig":"' + str(s_int) + '","local_resp":"' + str(d_int) + '","missed_bytes":"0","history":"' + history + '","orig_pkts":"'+ str(pkts_out) +'","orig_bytes":"'+ str(bytes_out) +'","orig_ip_bytes":"'+ str(ip_bytes_out) +'","resp_pkts":"'+ str(pkts_in) +'","resp_bytes":"'+ str(bytes_in) +'","resp_ip_bytes":"'+ str(ip_bytes_in) +'","corelight_shunted":"false","orig_l2_addr":"N/A","resp_l2_addr":"N/A","community_id":"N/A"}'

    #print("About to write the conn log file")
    conn_log_path = file_output_path + "conn_log.txt"
    #conn_log_path = "c:/Users/palin/OneDrive/Desktop/python_scripts/conn_log.txt"
    append_text_to_file(conn_log_path, logFormat)

def writeHTTPLog(randHost, src_port, dest_port, src_ip, dest_ip, s_int, d_int, file_id, uid, status_code, method, uri, referrer, status_msg, userAgent, the_time):
    #print("Writing HTTP Log")

    request_body_len = getRandomNumber(0, 1758)
    response_body_len = getRandomNumber(0, 9422)

    logFormat = '{"ts":"' + str(the_time) + '","uid":"' + str(uid) + '","id.orig_h":"' + src_ip + '","id.orig_p":"' + str(src_port) + '","id.resp_h":"' + dest_ip + '","id.resp_p":"' + str(dest_port) + '","trans_depth":"1","method":"' + str(method) + '","referrer":"' + str(referrer) + '","url":"' + str(uri) + '","uri":"' + str(uri) + '","version":"1.0","user_agent":"' + str(userAgent) + '","request_body_len":"' + str(request_body_len) + '","response_body_len":"'+ str(response_body_len) + '","status_code":"' + str(status_code) + '","status_msg":"' + str(status_msg) + '","tags":[],"resp_fuids":["' + str(file_id) + '"],"resp_mime_types":["text/plain"]}'
    conn_log_path = file_output_path + "http_log.txt"
    #conn_log_path = "c:/Users/palin/OneDrive/Desktop/python_scripts/http_log.txt"
    append_text_to_file(conn_log_path, logFormat)

def writeConnLog(randHost, src_port, dest_port, src_ip, dest_ip, s_int, d_int, proto, service, history, conn_state, uid, the_time):
    #print("Writing Conn Log")
    #print(src_ip)
    #proto = proto.ToLower()
    bytes_in = getRandomNumber(0, 148000)
    ip_bytes_in = bytes_in * 1.65
    pkts_in = getRandomNumber(0, 140)
    bytes_out = getRandomNumber(49, 16805)
    ip_bytes_out = bytes_out * 1.75
    pkts_out = getRandomNumber(1,81)
    
    logFormat = '{"ts":"' + str(the_time) + '","site":"' + str(randHost) + '","uid":"' + str(uid) + '","id.orig_h":"' + src_ip + '","id.orig_p":"'+ str(src_port) +'","id.resp_h":"' + dest_ip + '","id.resp_p":"' + str(dest_port) + '","proto":"' + proto + '","service":"'+ service + '","conn_state":"' + "SF" + '","local_orig":"' + str(s_int) + '","local_resp":"' + str(d_int) + '","missed_bytes":"0","history":"ShADadFf","orig_pkts":"'+ str(pkts_out) +'","orig_bytes":"'+ str(bytes_out) +'","orig_ip_bytes":"'+ str(ip_bytes_out) +'","resp_pkts":"'+ str(pkts_in) +'","resp_bytes":"'+ str(bytes_in) +'","resp_ip_bytes":"'+ str(ip_bytes_in) +'","corelight_shunted":"false","orig_l2_addr":"N/A","resp_l2_addr":"N/A","community_id":"N/A"}'
        
    conn_log_path = file_output_path + "conn_log.txt"
    #conn_log_path = "c:/Users/palin/OneDrive/Desktop/python_scripts/conn_log.txt"
    append_text_to_file(conn_log_path, logFormat)

def writeFilesLog(randHost, src_ip, dest_ip, s_int, d_int, uid, mime_type, md5, the_time, file_id):
    #print("Writing files log")

    logFormat = '{"ts":"' + str(the_time) + '","site":"' + str(randHost) + '","fuid":"' + file_id + '","tx_hosts":["' + src_ip + '"],"rx_hosts":["' + dest_ip + '"],"conn_uids":["' + uid + '"],"source":"SSL","depth":"0","analyzers":["MD5","SHA256","X509","SHA1"],"mime_type":"' + mime_type + '","duration":"0.0","local_orig":"true","is_orig":"true","seen_bytes":"1565","missing_bytes":"0","overflow_bytes":"0","timedout":"false","md5":"' + md5 + '","sha1":"4a7338b82162a8b6386de7e88f8297530bc20a46","sha256":"a884b37a542d8e1c085b577b241d4d0362e1d33b0bf3061130ecd52114fcc12b"}'

    conn_log_path = file_output_path + "files_log.txt"
    #conn_log_path = "c:/Users/palin/OneDrive/Desktop/python_scripts/files_log.txt"
    append_text_to_file(conn_log_path, logFormat)

def writeIntel(mime_type, description, indicatorType, indicatorSeen, intelSource, uid, fuid, indicator, src_ip, dest_ip, dest_port, src_port, the_time):
    #print("in function")

    logFormat = '{"ts":"' + str(the_time) + '","uid":"' + str(uid) + '","fuid":"' + fuid + '","intelSource":"' + intelSource + '","indicator":"' + indicator+ '","mime_type":"' + mime_type + '","Description":"' + description + '","indicatorType":"' + indicatorType + '","indicatorSeen":"' + indicatorSeen + '","src_ip":"' + src_ip + '","src_port":"' + str(src_port) + '","dest_ip":"' + dest_ip + '","dest_port":"' + str(dest_port) + '"}'

    conn_log_path = file_output_path + "intel_log.txt"    
   
    append_text_to_file(conn_log_path, logFormat)
           
def writeDNSLog(src_port, dest_port, src_ip, dest_ip, uid, query, answer, the_time):
    #print("in function")

    logFormat = '{"_path":"dns","_system_name":"S1CORL1","_write_ts":"' + str(the_time) + '","ts":"' + str(the_time) + '","uid":"' + str(uid) + '","id.orig_h":"' + src_ip + '","id.orig_p":"' + str(src_port) + '","id.resp_h":"' + dest_ip + '","id.resp_p":"' + str(dest_port) + '","proto":"udp","trans_id":1306,"rtt":0.0068359375,"query":"' + query + '","qclass":1,"qclass_name":"C_INTERNET","qtype":1,"qtype_name":"A","rcode":0,"rcode_name":"NOERROR","AA":true,"TC":false,"RD":true,"RA":true,"Z":0,"answers":["' + answer + '"],"TTLs":[3600.0],"rejected":false}'

    conn_log_path = file_output_path + "dns_log.txt"    
    #conn_log_path = "c:/Users/palin/OneDrive/Desktop/python_scripts/dns_log.txt"
    append_text_to_file(conn_log_path, logFormat)

def writeCorelightNotice():
    print("in function")
    
def writeEstreamer(the_time, uid, src_port, dest_port, src_ip, dest_ip, msg, sid, class_desc):
    #print("in function")

    logFormat = '{"rec_type":"400","_system_name":"S1CORL1","_write_ts":"' + str(the_time) + '","ts":"' + str(the_time) + '","uid":"' + uid + '","src_ip":"' + src_ip + '","src_port":"' + str(src_port) + '","dest_ip":"' + dest_ip + '","dest_port":"' + str(dest_port) + '","proto":"tcp","msg":"' + msg + '","sid":"' + sid +'","class_desc":"' + class_desc + '"}'

    conn_log_path = file_output_path + "estreamer_log.txt"    
    append_text_to_file(conn_log_path, logFormat)

def writeSQLServerLog(randHost, src_port, dest_port, src_ip, dest_ip, uid, the_time, query):
    print("in Function")

    logFormat = '{"ts":"' + str(the_time) + '","site":"' + str(randHost) + '","uid":"' + str(uid) + '","id.orig_h":"' + src_ip + '","id.orig_p":'+ str(src_port) +',"id.resp_h":"' + dest_ip + '","id.resp_p":' + str(dest_port) + ',"header_type":"Transaction Descriptor","query":"' + query + '"}'
    conn_log_path = file_output_path + "sql_log.txt"
    #conn_log_path = "c:/Users/palin/OneDrive/Desktop/python_scripts/sql_log.txt"
    append_text_to_file(conn_log_path, logFormat)

def writeRDPLog(randHost, result, src_port, dest_port, src_ip, dest_ip, uid, the_time):
    #print("in function")
    ###Fix ME###
    #logFormat= '{"ts":"someTime"}'
    logFormat = '{"ts":"' + str(the_time) + '","site":"' + str(randHost) + '","uid":"' + str(uid) + '","id.orig_h":"' + src_ip + '","id.orig_p":"' + str(src_port) + '","id.resp_h":"' + dest_ip + '","id.resp_p":"' + str(dest_port) + '","cookie":"testing","result":"' + result + '","security_protocol":"RDP","keyboard_layout":"English - United States","client_build":"client_build-30030","client_name":"MBP2017.lan.eucl","client_dig_product_id":"","desktop_width":"3440","desktop_height":"1440","requested_color_depth":"24bit","cert_type":"RSA","cert_count":"1","cert_permanent":true,"encryption_level":"Client compatible","encryption_method":"128bit"}'
    
    conn_log_path = file_output_path + "rdp_log.txt"
    #conn_log_path = "c:/Users/palin/OneDrive/Desktop/python_scripts/rdp_log.txt"
    append_text_to_file(conn_log_path, logFormat)
    
def createPingScan(src_ip, dest_ip, scan_src_port, scan_dest_port, scanInternal, scanDMZ, proto, service, the_time):
    
    if scanInternal == "TRUE":
        for nAddress in ListOfInventory:
            #print("inside internal addresses")
            if nAddress.location == "internal":
                uid = generate_uid()
                dest_ip = nAddress.ip
                current_time = int(time.time())

                writeConnLogICMP("site1", current_time, scan_src_port, scan_dest_port, src_ip, dest_ip, uid, "true", proto, service, "SF")  

           
    print(scanDMZ)    
    if scanDMZ == "TRUE":
        for nAddress in ListOfInventory:
            #print("inside dmz addresses")
            
            print(nAddress.location)
            if nAddress.location == "dmz":
                #print("I am in Steve")
                uid = generate_uid()
                dest_ip = nAddress.ip
                current_time = int(time.time())

                writeConnLogICMP("site1", current_time, scan_src_port, scan_dest_port, src_ip, dest_ip, uid, "true", proto, service, "SF")            
          
def writeConnLogICMP(randHost, the_time, scan_src_port, scan_dest_port, src_ip, dest_ip, uid, d_int, proto, service, conn_state):
    
    bytes_in = 96
    ip_bytes_in = bytes_in + 8
    pkts_in = 1
    bytes_out = 36
    ip_bytes_out = bytes_out + 8
    pkts_out = 1
    someTime = the_time   

    #$test_cid = GetCommunityID -src_ip $s_ip -src_port $s_port -dest_ip $d_ip -dest_port $d_port -proto $proto

    # added this to fix missing mac addresses
    #$src_ip_index = Get-IP_Index -ip_list $InternalScanner.IP -device_ip $s_ip
    #$dest_ip_index = Get-IP_Index -ip_list $InternalAddresses.IP -device_ip $d_ip

    logFormat = '{"ts":"' + str(someTime) + '","site":"' + str(randHost) + '","uid":"' + str(uid) + '","id.orig_h":"' + src_ip + '","id.orig_p":"'+ scan_src_port +'","id.resp_h":"' + dest_ip + '","id.resp_p":"' + str(scan_dest_port) + '","proto":"' + proto + '","service":"'+ service + '","conn_state":"' + conn_state + '","missed_bytes":"0","orig_pkts":"' + str(pkts_out) + '","orig_bytes":"' + str(bytes_out) + '","orig_ip_bytes":"' + str(ip_bytes_out) + '","resp_pkts":"' + str(pkts_in) + '","resp_bytes":"' + str(bytes_in) + '","resp_ip_bytes":"' + str(ip_bytes_in) + '","corelight_shunted":"false","log_source":"line825"}' 

    conn_log_path = file_output_path + "conn_log.txt"
    #conn_log_path = "c:/Users/palin/OneDrive/Desktop/python_scripts/conn_log.txt"
    append_text_to_file(conn_log_path, logFormat)

def addTime(timeInSeconds):
     # Get current time in epoch format
    current_time_epoch = int(time.time())

    # Add sixty seconds to the current time
    new_time_epoch = current_time_epoch + timeInSeconds

    # Convert the new time back to a readable format
    new_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(new_time_epoch))

    # Print the results
    print(f"Current Time (Epoch): {current_time_epoch}")
    print(f"New Time (Epoch)    : {new_time_epoch}")
    print(f"New Time            : {new_time}")
    return new_time_epoch

def TimedLogGenerator():
    try:
        minutes = int(input("Enter the number of minutes: "))
        if minutes <= 0:
            print("Please enter a positive number of minutes.")
        else:
            seconds = minutes * 60

            start_time = time.time()

            # Define the duration of the loop in seconds (60 seconds in this case)
            duration = seconds
            #duration = 10
        
        while (time.time() - start_time) < duration:
                
            time.sleep(1)
            SomeRandom = getRandomNumber(0,10)
            if SomeRandom==1:
                writeStandaloneConnLog("site1")
            elif SomeRandom==2:
                writeHTTPEvent("site2")
            elif SomeRandom==3:
                CreateSShEvent("site3")
            elif SomeRandom==4:
                CreateMicrosoftSQLEvent("site4")
            elif SomeRandom==5:
                CreateVPNEvent("site5")
            elif SomeRandom==6:
                createRDPEvent("site6")
            
            
       
         
    except ValueError:
        print("Invalid input. Please enter a valid number of minutes.")

    
    
### START OF CODE ###
### Set Variables ###

#file_output_path = "/home/troy/temp/inventory_creation/"
file_output_path = "/opt/scripts/inventory_creation/"
#file_output_path = "E:/Temp/"

#file_path = "E:/Temp/script_scenarioDetails.csv"
file_path = "/opt/scripts/script_scenarioDetails.csv"

csv_data = read_csv_file(file_path)

#file_path_meta = "E:/temp/script_scenarioMeta.csv"
file_path_meta = "/opt/scripts/script_scenarioMeta.csv"

meta_csv_data = read_csv_file(file_path_meta)

#file_path_inventory = "E:/temp/script_inventory_generation.csv"
file_path_inventory = "/opt/scripts/script_inventory_generation.csv"
inventory_csv_data = read_csv_file(file_path_inventory)

ListOfIdS_Alerts = []
ListOfMetaIDS = []
ListOfInventory = []

InternalAddressCount = 0
ExternalAddressCount = 0
DMZAddressCount = 0

InternalAddresses = []
InternalScanner = []
DMZAddresses = []
ExternalAddresses = []

i = 0
while i < len(inventory_csv_data):
   
    nInventory = inventory_item(inventory_csv_data[i][0], inventory_csv_data[i][1], inventory_csv_data[i][2], inventory_csv_data[i][3], inventory_csv_data[i][4], inventory_csv_data[i][5], inventory_csv_data[i][6], inventory_csv_data[i][7], inventory_csv_data[i][8])
    
    if nInventory.location == "internal":
        InternalAddressCount += 1
    elif nInventory.location == "external": 
        ExternalAddressCount += 1
    elif nInventory.location == "dmz":
        DMZAddressCount += 1

    ListOfInventory.append(nInventory)
    i += 1

i = 0
while i < len(meta_csv_data):
    nMeta = meta_ids(meta_csv_data[i][0], meta_csv_data[i][1], meta_csv_data[i][2], meta_csv_data[i][3])
    ListOfMetaIDS.append(nMeta)
    i += 1

i = 0

#for i in csv_data:
#    nIDSAlert = ids_alert(csv_data[i][0],csv_data[i][1],csv_data[i][2],csv_data[i][3],csv_data[i][4],csv_data[i][5],csv_data[i][6],csv_data[i][7],csv_data[i][8],csv_data[i][9],csv_data[i][10],csv_data[i][11],csv_data[i][12],csv_data[i][13],csv_data[i][14],csv_data[i][15],csv_data[i][16],csv_data[i][17],csv_data[i][18],csv_data[i][19],csv_data[i][20],csv_data[i][21],csv_data[i][22],csv_data[i][23],csv_data[i][24],csv_data[i][25],csv_data[i][26],csv_data[i][27])    
#    ListOfIdS_Alerts.append(nIDSAlert)    
while i < len(csv_data):
    nIDSAlert = ids_alert(csv_data[i][0],csv_data[i][1],csv_data[i][2],csv_data[i][3],csv_data[i][4],csv_data[i][5],csv_data[i][6],csv_data[i][7],csv_data[i][8],csv_data[i][9],csv_data[i][10],csv_data[i][11],csv_data[i][12],csv_data[i][13],csv_data[i][14],csv_data[i][15],csv_data[i][16],csv_data[i][17],csv_data[i][18],csv_data[i][19],csv_data[i][20],csv_data[i][21],csv_data[i][22],csv_data[i][23],csv_data[i][24],csv_data[i][25],csv_data[i][26],csv_data[i][27])
    ListOfIdS_Alerts.append(nIDSAlert)
   
    i += 1





#addTime(60)
#addTime(600)


#print(generate_uid())

GenerateInventory()
Write_All_Scenario()
#Write_Custom_Scenario(1, "Some Scenario", "Time")

TimedLogGenerator()


#generate inventory
#generate os
#generate software info
#generate useragent
#generate anomaly ja3
#generate anomaly filehash
