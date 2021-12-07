package fr.networkanalyzer.application;

import java.io.File;
import java.util.Scanner;

import fr.networkanalyzer.model.AnalyzerParser;
import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;

public class TerminalMain {
	public static void main(String[] args) {
		
		Scanner sc = new Scanner(System.in);
		System.out.print("veuiller saisir le nom du fichier: ");
		File file  = new File(sc.nextLine());
		
		while(file == null || !file.exists() || file.isDirectory()) {
			System.out.println("is not a name file");
			System.out.print("veuiller saisir le nom du fichier: ");
			file  = new File(sc.nextLine());
		}
		
		try {
			System.out.println(AnalyzerParser.parse(file));
			
			
		} catch (NetworkAnalyzerException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
			
			
		
	}
}
