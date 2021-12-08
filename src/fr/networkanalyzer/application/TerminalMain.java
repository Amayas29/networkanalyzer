package fr.networkanalyzer.application;

import java.io.File;
import java.util.Scanner;

import fr.networkanalyzer.model.Analyzer;
import fr.networkanalyzer.model.AnalyzerParser;
import fr.networkanalyzer.model.Frame;
import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;

public class TerminalMain {
	public static void main(String[] args) {

		System.out.println(
				"--------------------- Version Terminal | autors : Amayas SADI ans Hamid KOLLI ---------------------\n\n\n");

		Scanner sc = new Scanner(System.in);

		File file = null;

		Analyzer analyzer = null;

		while (true) {
			System.out.print("\t - please enter file name: ");
			file = new File(sc.nextLine());
			if (file != null && file.exists() && !file.isDirectory()) {
				try {
					analyzer = AnalyzerParser.parse(file);
				} catch (NetworkAnalyzerException e1) {
					System.out.println("\t \t the format of this file is not compatible \n");
					continue;
				}
				break;
			}

			System.out.println("\t \t the file name is not valid \n");

		}

		while (true) {
			System.out.println("***Please press ENTER to continue***");
		
			sc.nextLine();
			System.out.println("\tplease choose one of this numbers : ");
			displayMain();
			int choose;
			try {
				choose = sc.nextInt();
			} catch (Exception e) {
				continue;
			}

			switch (choose) {
			case 0: {
				System.out.println(analyzer);
				sc.nextLine();
				break;
			}
			case 1: {
				System.out.println("\t\t please enter the id frame");
				try {
					int c = sc.nextInt();
					boolean b = true;
					for (Frame f : analyzer.getFrames()) {
						if (f.getId() == c) {
							System.out.println(f);
							b = false;
							break;

						}
					}
					if (b) {
						System.out.println("\t\t the frame doesn't exist");
						
					}

				} catch (Exception e) {
					System.out.println("\t\t invalid number \n");
				}
				sc.nextLine();
				continue;

			}
			case 2: {
				try {
					AnalyzerParser.saveAll(analyzer);
				} catch (NetworkAnalyzerException e) {
					
				}
				
				continue;
			}
			case 3: {
				System.out.println("\t\t please enter the id frame");
				try {
					int c = sc.nextInt();
					boolean b = true;
					for (Frame f : analyzer.getFrames()) {
						if (f.getId() == c) {
							AnalyzerParser.save(f);
							b = false;
							break;

						}
					}
					if (b) {
						System.out.println("\t\t the frame doesn't exist");
						
					}

				} catch (Exception e) {
					System.out.println("\t\t invalid number \n");
				}
				sc.nextLine();
				continue;
			}
			case 4: {
				System.out.println("\t Good bye");
				System.exit(0);
				
				continue;
			}
			default:
				continue;
			}

		}

	}

	public static void displayMain() {

		System.out.println("\t+-------------------+");
		System.out.println("\t| 0- display frames |");
		System.out.println("\t| 1- display frame  |");
		System.out.println("\t| 2- save frames    |");
		System.out.println("\t| 3- save frame     |");
		System.out.println("\t| 4- exit           |");
		System.out.println("\t+-------------------+");

	}
}
