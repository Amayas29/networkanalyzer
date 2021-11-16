package fr.networkanalyzer.model;

import java.io.File;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.exceptions.NetworkAnalyzerFileErrorsException;

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
//		throw new NetworkAnalyzerException("Parser error");

		// Boucle
		return new Analyzer();
	}
}
