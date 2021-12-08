package fr.networkanalyzer.model.visitors;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.layers.protocols.Dhcp;
import fr.networkanalyzer.model.layers.protocols.Dns;
import fr.networkanalyzer.model.layers.protocols.Ethernet;
import fr.networkanalyzer.model.layers.protocols.Ip;
import fr.networkanalyzer.model.layers.protocols.Udp;

public interface ILayerVisitor {

	public void visit(Ethernet ethernet) throws NetworkAnalyzerException;

	public void visit(Ip ip) throws NetworkAnalyzerException;

	public void visit(Udp udp) throws NetworkAnalyzerException;

	public void visit(Dhcp dhcp) throws NetworkAnalyzerException;

	public void visit(Dns dns) throws NetworkAnalyzerException;

}