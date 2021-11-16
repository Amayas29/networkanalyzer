package fr.networkanalyzer.model;

import java.io.File;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.exceptions.NetworkAnalyzerFileNotFoundException;
import fr.networkanalyzer.model.exceptions.NetworkAnalyzerNotFileException;

public class AnalyzerParser {
	private AnalyzerParser() {}
	
	public static void verifyFile(File f) throws NetworkAnalyzerException{
		if(f == null||! f.exists())
			throw new NetworkAnalyzerFileNotFoundException();
		if(!f.isFile())
			throw new NetworkAnalyzerNotFileException();
	}
	
	public static Analyzer parse(File file) throws NetworkAnalyzerException {
		throw new NetworkAnalyzerException("parser error");
	}
}
