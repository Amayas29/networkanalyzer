package fr.networkanalyzer.model.layers;

import fr.networkanalyzer.model.layers.protocols.Arp;
import fr.networkanalyzer.model.layers.protocols.Dhcp;
import fr.networkanalyzer.model.layers.protocols.Dns;
import fr.networkanalyzer.model.layers.protocols.Ethernet;
import fr.networkanalyzer.model.layers.protocols.Http;
import fr.networkanalyzer.model.layers.protocols.Icmp;
import fr.networkanalyzer.model.layers.protocols.Imap;
import fr.networkanalyzer.model.layers.protocols.Ip;
import fr.networkanalyzer.model.layers.protocols.Tcp;
import fr.networkanalyzer.model.layers.protocols.Udp;

public interface ILayerVisitor {

	public void visit(Arp arp);

	public void visit(Dhcp dhcp);

	public void visit(Dns dns);

	public void visit(Ethernet ethernet);

	public void visit(Http http);

	public void visit(Icmp icmp);

	public void visit(Imap imap);

	public void visit(Ip ip);

	public void visit(Tcp tcp);

	public void visit(Udp udp);

}
