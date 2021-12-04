package fr.networkanalyzer.model;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.exceptions.NetworkAnalyzerFileErrorsException;
import fr.networkanalyzer.model.layers.protocols.Ethernet;
import fr.networkanalyzer.model.tools.ParsingTools;
import fr.networkanalyzer.model.visitors.LayerParserVisitor;

public class AnalyzerParser {

	public static final String FILE_NAME = "networkAnalyzerSavedFrames.txt";

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

		file = ParsingTools.reorganizeFile(file);

		Analyzer analyzer = new Analyzer();
		String line;
		Frame frame;
		Ethernet ethernet;
		LayerParserVisitor parser = new LayerParserVisitor();
		try (BufferedReader reader = new BufferedReader(new FileReader(file))) {

			while ((line = reader.readLine()) != null) {
				parser.setLine(line);
				ethernet = new Ethernet();
				try {
					ethernet.accept(parser);
				} catch (NetworkAnalyzerException e) {
					analyzer.addError(e.getMessage());
					System.out.println(e.getMessage());
					continue;
				}

				frame = new Frame();
				frame.setLayerDataLink(ethernet);
				analyzer.addFrame(frame);
			}

		} catch (IOException e) {
			throw new NetworkAnalyzerException(e.getMessage());
		} finally {
			file.delete();
		}

		return analyzer;
	}

	public static void save(Frame frame) throws NetworkAnalyzerException {
		
		try (BufferedWriter bf = new BufferedWriter(new FileWriter(new File("Trame " + frame.getId())))){
			save(frame, bf);
		} catch (NetworkAnalyzerException | IOException e) {
			throw new NetworkAnalyzerException("writer does not work");
		}
	}

	public static void save(Frame frame, BufferedWriter bwFile) throws NetworkAnalyzerException {
		if (frame == null)
			throw new NetworkAnalyzerException("frame does not exist");
		try {
			bwFile.write(frame.toString());
			System.out.println(frame);
		} catch (IOException e) {
			throw new NetworkAnalyzerException("writer does not work");
		}
	}

	public static void saveAll(Analyzer analyzer) throws NetworkAnalyzerException {
		try (BufferedWriter bf = new BufferedWriter(new FileWriter(new File("Analyze")))) {
			if (analyzer == null)
				throw new NetworkAnalyzerException("frame does not exist");
			for (Frame frame : analyzer.getFrames()) {
				save(frame, bf);
			}
		} catch (Exception e) {
		}
	}

}
