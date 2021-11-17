package fr.networkanalyzer.model;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Iterator;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.exceptions.NetworkAnalyzerFileErrorsException;
import fr.networkanalyzer.model.layers.Ethernet;

public class AnalyzerParser {
	private AnalyzerParser() {
	}

	public static void verifyFile(File f) throws NetworkAnalyzerFileErrorsException {
		if (f == null || !f.exists())
			throw new NetworkAnalyzerFileErrorsException("File doesn't exist");

		if (!f.isFile())
			throw new NetworkAnalyzerFileErrorsException("Node isn't a file");

		if (!f.canRead())
			throw new NetworkAnalyzerFileErrorsException("File can't be read");
	}

	public static Analyzer parse(File file) throws NetworkAnalyzerException {
		Analyzer analyzer = new Analyzer();
//		try (BufferedReader bufferedReader = new BufferedReader(new FileReader(file))) {
//			String line;
//			int offset = 0;
//			Frame frame = null;
//			while ((line = bufferedReader.readLine()) != null) {
//				String[] data = line.split(" ");
//
//				int parsedOffset = Integer.parseInt(data[0], 10);
//
//				if (parsedOffset != 0) {
//					continue;
//				}
//
////				frame = new Frame();
////				frame.parse(file);
////				analyzer.addFrame(frame);
//			}
//
//		} catch (IOException e) {
//			throw new NetworkAnalyzerFileErrorsException(e.getMessage());
//		}
		Frame f = new Frame();
		Ethernet ethernet = new Ethernet();
		f.setLayerDataLink(ethernet);
		ethernet.addField(Ethernet.TYPE, new Field("t", "", "IPV4", 0));
		ethernet.parse(null);
		analyzer.addFrame(f);

		return analyzer;
//		throw new NetworkAnalyzerException("Parse Error");
	}
}
