package fr.networkanalyzer.model.tools;

import fr.networkanalyzer.model.fields.Entry;

public enum TypeDhcp {
	
		OFFER(new Entry("Offer",2)),
		REQUEST(new Entry("Request",3)),
		DECLINE(new Entry("Decline",4)),
		ACK(new Entry("ACK",5)),
		NAK(new Entry("NAK",6)),
		RELEASE(new Entry("Release",7)),
		INFORM(new Entry("Inform",8)),
		FORCE(new Entry("Force",9)),
		LEASE(new Entry("Lease",10)),
		UNKNOW(new Entry("Unknow", -1));
		

	private Entry type;
	private TypeDhcp(Entry entry) {
		type = entry;
	}
	
	public static Entry getEntryByCode(int code)  {
		TypeDhcp[] options = values();
		for (int j = 0; j < options.length; j++) 
			if(code == options[j].type.getValue())
				return options[j].type;
		
		return TypeDhcp.UNKNOW.type;
	}
	
}
