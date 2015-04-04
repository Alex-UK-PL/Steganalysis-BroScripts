## IPID_StegDetect.bro
## Version: 0.42
## Author: Alexander Drabek, drabek.a@o2.pl
## https://github.com/Alex-UK-PL/Steganalysis-BroScripts
## 
## !CAUTION! The packet level analysis is performed!    !CAUTION!
## !CAUTION! Author is not responsible losses which,    !CAUTION!
## !CAUTION!  are caused by using provided script.      !CAUTION! 
## !CAUTION! This script may result in false positives! !CAUTION!
## 
## This script analyses for any signs of usage of Covert_tcp(IPID method)
## This include :
## -Checking if the Connection is rejected
## -Checking & (Decoding to ASCII) value of IP ID 
## 
## A usage of Covert_tcp means concealment of information and its transmission. 
## 


##Impr: we could use event Steg_IPID_tcpCovert (c : connection , packet etc)
##IMPr : AM I fine with the event and log OR do I have to alter/ redef notices ?
# check what is the UID in c$id$resp_p (protocol) 
#connid and cuid is different thing - conn is the flow of connection after init.
#TEST : Connection_SYN_packet


module Steg_IPID_tcpCovert;
#why the heck i still need to do packet level analysis 
#if this is IP IP it should be visible on a CON level. v.05?!
export {
    redef enum Log::ID += { LOG };
    global testConState : string = "";
    global testConID: string = "";
    global REJ_count: count = 0;
    type Info: record {
      ts: time &log;
      UID_val: string &log;
      IPID_val: count &log;
      ASCII_code: count &log;
    };
}

event bro_init() 
{
 Log::create_stream(LOG, [$columns=Info]);
}


event connection_state_remove(c: connection)
{
  #can not optimize with connection_rejected as this may be evaded with simple Covert_tcp source code changes

 testConState="other";
  if (c$conn$conn_state == "REJ")  
  {
   testConState="REJ";
   #testConID= c$uid;
  }
}

event new_packet(c: connection, p: pkt_hdr)
{
  #the below line will give error if packet is not IP like ARP
  #not having effect on analysis #is ascii() function? instead of <=128 && 
 local testIPID=0;
 if ((is_tcp_port(c$id$resp_p) || is_tcp_port(c$id$orig_p)) ) testIPID=p$ip$id/256; 
  if (testIPID<= 128 && testIPID > 0 && testConState=="REJ" && c$history == "")
  {
  ##CONSOLE OUTPUT##
    print fmt("MEans hex ASCII: %s ",testIPID );
    ++REJ_count;
    print testConState;
    print c$uid;
    print REJ_count;
  ##END OF CONSOLE OUTPUT##
    local mes1 = [$ts = network_time(),$UID_val=c$uid , $IPID_val = p$ip$id,$ASCII_code=testIPID ];
    Log::write(LOG, mes1);  
    }                 
}
 



#----------------COMMENTS-----------------------#
#if (testConID==c$uid) { 
#  print "this claim to be OK !?";#happens with WHEN!?!
#  print c$uid; print testConID;
#  }
#invoke the new script with packet level analysis or
#OR
#invoke next event !!!
#or do it via function and then invoke function and event-detect_MHR.bro
# i could go global x for pkt header and then
#invoke covert_optimal - but this will miss the point
#of not processing every packet
# conn state _remove//connection rejected
#event connection_state_remove( c: connection)
#{
 #if (c$conn$conn_state == "REJ")
 # print"test hurra";
 #global cstat = c$conn$conn_state;
 #   covert_tcp_optimal();

  #i need to return F or T if function
  #the tcp_packet instead of new_packet still too expensive