package fr.networkanalyzer.model.decodes;

import fr.networkanalyzer.model.fields.Entry;

public class ArpDecoded extends Decode{
static {
	put(0,"Reserved");
	put(1,"REQUEST");
	put(2,"REPLY");
	put(3,"request Reverse");
	put(4,"reply Reverse");
	put(5,"DRARP-Request");
	put(6,"DRARP-Reply");
	put(7,"DRARP-Error");
	put(8,"InARP-Request");
	put(9,"InARP-Reply");
	put(10,"ARP-NAK");
	put(11,"MARS-Request");
	put(12,"MARS-Multi");
	put(13,"MARS-MServ");
	put(14,"MARS-Join");
	put(15,"MARS-Leave");
	put(16,"MARS-NAK");
	put(17,"MARS-Unserv");
	put(18,"MARS-SJoin");
	put(19,"MARS-SLeave");
	put(20,"MARS-Grouplist-Request");
	put(21,"MARS-Grouplist-Reply");
	put(22,"MARS-Redirect-Map");
	put(23,"MAPOS-UNARP");
	put(24,"OP_EXP1");
	put(25,"OP_EXP2");
	put(-1,"UNKNOW");
	
}

public static Entry<String,Integer> getType(int i){
	return Decode.getType(i);
}
}
