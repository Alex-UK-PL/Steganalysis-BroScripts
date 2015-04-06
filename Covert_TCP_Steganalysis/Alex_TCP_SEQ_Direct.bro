## TCP_StegDetect.bro
## Version : 0.42
## Author : Alexander Drabek, drabek.a@o2.pl
## https://github.com/Alex-UK-PL/Steganalysis-BroScripts
## 
## !CAUTION! The packet level analysis is performed!    !CAUTION!
## !CAUTION! Author is not responsible losses which,    !CAUTION!
## !CAUTION!  are caused by using provided script.      !CAUTION! 
## !CAUTION! This script may result in false positives! !CAUTION!
## 
## This script analyses for any signs of usage of Covert_tcp(SEQ method)
## This include :
##
## PROBLEM : A use of tcp_packet is useless due to relative seq nr calculate by BRO IDS
## TO DO: optimal via tcp_packet event however keep the original TCP SEQ value !

##Impr: we could use event Steg_IPID_tcpCovert (c : connection , packet etc)
# check what is the UID in c$id$resp_p (protocol) 
#con state rem is later so the REJ==true is executed on next packet not necessary . stego packet.
#connid and cuid is different thing - conn is the flow of connection after init.

#@load base/frameworks/logging - displays warnings - above commented lines 
module Steg_IPSEQ_tcpCovert;

export {
    redef enum Log::ID += { LOG };
    global testConState : string = "";
    global testConID: string = "";
    global REJ_count: count = 0;
    type Info: record {
      ts: time &log;
      UID_val: string &log;
      IPSEQ_val: count &log;
      ASCII_code: count &log;
    };
}

event bro_init() 
{
 Log::create_stream(LOG, [$columns=Info]);
}

 event connection_state_remove(c: connection)
{
  #can not optimize with connection_rejected 
  #as this may be evaded with simple Covert_tcp source code changes
 testConState="other";
 # testConID="";
 if (c$conn$conn_state == "REJ")  
   {
   testConState="REJ";
   #testConID= c$uid;
   }
}


event new_packet(c: connection, p: pkt_hdr)
{

  # if (testConState=="REJ1st") testConState=="REJ";
  #if (REJ_count==0) testConState=="REJ";

  #not having effect on analysis && c$history == ""
  local testIPSEQ =0;
  if ( (is_tcp_port(c$id$resp_p) || is_tcp_port(c$id$orig_p)) && testConState=="REJ") testIPSEQ= p$tcp$seq/16777216;

 if (testIPSEQ<= 128  && testIPSEQ > 0)
  {

  ##CONSOLE OUTPUT## 
   print fmt("ASCII code: %s",testIPSEQ );
   ++REJ_count;
   print testConState;
   print c$uid;
   print REJ_count;
  ##END OF CONSOLE OUTPUT##

   local mes1 = [$ts = network_time(),$UID_val=c$uid , $IPSEQ_val = p$tcp$seq,$ASCII_code=testIPSEQ ];
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
 #global cstat = c$conn$conn_state;
  #i need to return F or T if function