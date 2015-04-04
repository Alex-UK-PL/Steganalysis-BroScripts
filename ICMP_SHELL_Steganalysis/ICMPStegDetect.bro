## ICMPStegDetect.bro
## Version : 0.5
## Author : Alexander Drabek, drabek.a@o2.pl
## https://github.com/Alex-UK-PL/Steganalysis-BroScripts
## 
## !CAUTION! The packet level analysis is performed!    !CAUTION!
## !CAUTION! Author is not responsible losses which,    !CAUTION!
## !CAUTION!  are caused by using provided script.      !CAUTION! 
## !CAUTION! This script may result in false positives! !CAUTION!
##

##ONLY ALG which resulted in false positives when tested with 4 ICMP conn
## possibility of another program utilizing ICMP .....CHECK!

module Steg_ICMP_SHELLv02;


export {
    redef enum Log::ID += { LOG };
    global Payload_CON_Table: table [count] of string ;# &default=0;
    global AlexINV_len: table [count] of string ;# &default=0;
    global Unique_icmpSET: set [string];
    global STEG_SET: set [string];
    
    type Info: record 
    {
      ts: time &log;
      Connection_UID_value: string &log;
      Sample_IP_Payload_Lenght: count &log;
    };
}

event bro_init() 
{
 Log::create_stream(LOG, [$columns=Info]);
}


event new_packet(c: connection, p: pkt_hdr)
{
#We could do a check on a p$icmp!="" - type of record with count in it
 if ( is_icmp_port(c$id$resp_p) || is_icmp_port(c$id$orig_p) )
  {
   #++ic_NewPACKETcount; #increment every packet
    if (Payload_CON_Table[p$ip$len] !=c$uid) AlexINV_len[p$ip$len] =c$uid;
   #TODO!! log me a payloads, which are creating a problem TODO!! -saving in 2nd table simply wont work...
   Payload_CON_Table[p$ip$len] = c$uid ;
   print fmt("PART OF connection : ID : %s ",c$uid );
   #print fmt("NewPACKETCON_ICMP : %s ",ic_NewPACKETcount );
 } 

}

#event connection_state_remove(c: connection) 
#{
#
#}

event bro_done()
{
 #TODO : Move the exec into other event [con state remove ?!]   
  for (lengICMP in Payload_CON_Table)
  {
      if (Payload_CON_Table[lengICMP] in  Unique_icmpSET)
        { 
         #print stego or/AND save stego ID
         add STEG_SET[Payload_CON_Table[lengICMP]];
        }
      if (Payload_CON_Table[lengICMP] !in  Unique_icmpSET)
        {
          add Unique_icmpSET[Payload_CON_Table[lengICMP]]; 
          local mes1 = [$ts = network_time(),$Connection_UID_value=Payload_CON_Table[lengICMP], $Sample_IP_Payload_Lenght = lengICMP];
          Log::write(LOG, mes1);  
        } 
   } 
  
  for (i in STEG_SET) #all unique icmp connections
   { 
     print fmt(" Steg Set entry%s",i);
   }
#network time may be sort of wrong as it is only giving the bro done time
}#