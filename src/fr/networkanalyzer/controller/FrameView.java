package fr.networkanalyzer.controller;

import fr.networkanalyzer.model.Frame;
import fr.networkanalyzer.model.layers.protocols.Ip;
import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleStringProperty;

public class FrameView {

	private SimpleIntegerProperty no;
	private SimpleStringProperty src;
	private SimpleStringProperty dest;
	private SimpleStringProperty protocol;
	private SimpleIntegerProperty lenght;

	private Frame frame;

	public FrameView(Frame frame, int index) {

		this.frame = frame;

		no = new SimpleIntegerProperty(index);
		src = new SimpleStringProperty(frame.getFieldNetwork(Ip.SRC_ADDRESS.NAME).getValueDecoded());
		dest = new SimpleStringProperty(frame.getFieldNetwork(Ip.DEST_ADDRESS.NAME).getValueDecoded());
		protocol = new SimpleStringProperty(frame.getEncapsulatedProtocol());
		lenght = new SimpleIntegerProperty(frame.getTotalLength());
	}

	public Integer getNo() {
		return no.get();
	}

	public String getDest() {
		return dest.get();
	}

	public String getProtocol() {
		return protocol.get();
	}

	public Integer getLenght() {
		return lenght.get();
	}

	public String getSrc() {
		return src.get();
	}

	public Frame getFrame() {
		return frame;
	}

}